"""Regression tests for the detections, on small synthetic Zeek logs.

Run with:  python -m unittest discover -s tests

Each false positive found on a real capture gets a test here, so a later
change to a threshold cannot silently bring it back.
"""

import base64
import codecs
from collections import Counter
import hashlib
import random
import tempfile
import unittest
import zipfile
from pathlib import Path

from pcaptriage.artifacts import collect_artifacts, zeek_script

from pcaptriage.correlation import build_narrative
from pcaptriage.decode import decode_findings
from pcaptriage.detections.beaconing import detect_beaconing
from pcaptriage.detections.host_mismatch import detect_host_mismatch
from pcaptriage.detections.mass_mailing import detect_mass_mailing
from pcaptriage.detections.post_delivery import detect_post_delivery
from pcaptriage.detections.suspicious_tls import detect_suspicious_tls
from pcaptriage.evaluate import score
from pcaptriage.indicators import build_indicators
from pcaptriage.detections.port_scan import detect_port_scan
from pcaptriage.detections.suspicious_download import detect_suspicious_download


def conn(src, dst, port, state="S0"):
    return {"id.orig_h": src, "id.resp_h": dst, "id.resp_p": port, "conn_state": state}


class PortScan(unittest.TestCase):
    def test_many_unanswered_ports_is_a_scan(self):
        logs = {"conn": [conn("10.0.0.66", "10.0.0.9", p, "REJ") for p in range(20, 120)]}
        found = detect_port_scan(logs)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")

    def test_busy_workstation_is_not_a_scan(self):
        # Regression: a client reaching 100 web servers (completed sessions)
        # used to be flagged because only the number of hosts was counted.
        rows = [conn("10.0.0.5", f"93.184.{i // 250}.{i % 250}", 443, "SF") for i in range(100)]
        rows += [conn("10.0.0.5", "10.0.0.1", p, "SF") for p in range(30)]
        self.assertEqual(detect_port_scan({"conn": rows}), [])

    def test_few_unanswered_among_many_completed_is_not_a_sweep(self):
        # Regression (seen on a real infection capture): 27 unanswered
        # connections to port 443 among ~180 completed ones is normal web noise.
        rows = [conn("10.0.0.5", f"203.0.{i // 250}.{i % 250}", 443, "S0") for i in range(27)]
        rows += [conn("10.0.0.5", f"198.51.{i // 250}.{i % 250}", 443, "SF") for i in range(150)]
        self.assertEqual(detect_port_scan({"conn": rows}), [])

    def test_real_host_sweep_is_detected(self):
        rows = [conn("10.0.0.66", f"10.0.1.{i}", 445, "S0") for i in range(1, 41)]
        found = detect_port_scan({"conn": rows})
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "medium")


class Decode(unittest.TestCase):
    def test_rot13_of_ordinary_text_is_noise(self):
        # Regression: ROT13 turns any readable text into other readable-looking
        # text, so it must only be reported when it reveals a keyword.
        logs = {"http": [{"uri": "/incidunt-consequatur/documents.zip",
                          "host": "example.org",
                          "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}]}
        self.assertEqual(decode_findings(logs), [])

    def test_rot13_flag_is_reported(self):
        logs = {"http": [{"user_agent": codecs.encode("the flag{rot13_ok}", "rot_13")}]}
        found = decode_findings(logs)
        self.assertEqual(len(found), 1)
        self.assertIn("flag{rot13_ok}", " ".join(found[0].evidence))

    def test_base64_flag_in_uri(self):
        blob = base64.b64encode(b"flag{base64_ok}").decode()
        self.assertEqual(len(decode_findings({"http": [{"uri": "/a?x=" + blob}]})), 1)

    def test_random_printable_junk_is_dropped(self):
        blob = base64.b64encode(b"xQ9#mK2!vLp@7zR^").decode()
        self.assertEqual(decode_findings({"http": [{"uri": "/n?x=" + blob}]}), [])


class Delivery(unittest.TestCase):
    def test_executable_from_internet_is_high(self):
        logs = {"files": [{"source": "HTTP", "is_orig": False,
                           "mime_type": "application/x-dosexec", "uid": "u1",
                           "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.4.4",
                           "seen_bytes": 100}]}
        found = detect_suspicious_download(logs)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")

    def test_archive_from_internal_server_is_ignored(self):
        logs = {"files": [{"source": "HTTP", "is_orig": False,
                           "mime_type": "application/zip", "uid": "u1",
                           "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.9"}]}
        self.assertEqual(detect_suspicious_download(logs), [])

    def test_upload_is_ignored(self):
        logs = {"files": [{"source": "HTTP", "is_orig": True,
                           "mime_type": "application/zip", "uid": "u1",
                           "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.4.4"}]}
        self.assertEqual(detect_suspicious_download(logs), [])


class MassMailing(unittest.TestCase):
    # Use routable addresses: documentation ranges such as 203.0.113.0/24 are
    # not "global", so the detector rightly ignores them.
    def test_one_relay_is_normal(self):
        smtp = [{"id.orig_h": "10.0.0.5", "id.resp_h": "45.33.0.9"}] * 5
        self.assertEqual(detect_mass_mailing({"smtp": smtp}), [])

    def test_many_external_servers_is_flagged(self):
        smtp = [{"id.orig_h": "10.0.0.5", "id.resp_h": f"45.33.0.{i}"} for i in range(1, 15)]
        found = detect_mass_mailing({"smtp": smtp})
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].hosts, ["10.0.0.5"])

    def test_attachment_names_are_decoded(self):
        smtp = [{"id.orig_h": "10.0.0.5", "id.resp_h": f"45.33.0.{i}"} for i in range(1, 15)]
        files = [{"source": "SMTP", "is_orig": True, "mime_type": "application/zip",
                  "id.orig_h": "10.0.0.5",
                  "filename": "=?UTF-8?B?Q2xhaW0uemlw?="}]  # "Claim.zip"
        found = detect_mass_mailing({"smtp": smtp, "files": files})
        self.assertIn("Claim.zip", " ".join(found[0].evidence))
        self.assertEqual(found[0].severity, "high")


class Narrative(unittest.TestCase):
    def test_host_spanning_phases_forms_a_chain(self):
        logs = {
            "files": [{"source": "HTTP", "is_orig": False, "mime_type": "application/zip",
                       "uid": "u1", "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.4.4"}],
            "smtp": [{"id.orig_h": "10.0.0.5", "id.resp_h": f"45.33.0.{i}"} for i in range(1, 15)],
        }
        findings = detect_suspicious_download(logs) + detect_mass_mailing(logs)
        chains = build_narrative(findings)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["phases"], ["Delivery", "Propagation"])


class Artifacts(unittest.TestCase):
    def _case(self, tmp, payload_writer):
        art = Path(tmp) / "zeek-logs" / "artifacts"
        art.mkdir(parents=True)
        payload_writer(art / "FUID1")
        return Path(tmp)

    def _logs(self, filename="docs.zip"):
        return {
            "files": [{"fuid": "FUID1", "uid": "u1", "ts": 1632501880.4,
                       "mime_type": "application/zip", "source": "HTTP", "is_orig": False,
                       "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.4.4", "filename": filename}],
            "http": [{"uid": "u1", "host": "evil.example", "uri": "/a/docs.zip"}],
        }

    def test_lists_archive_index_and_hashes(self):
        def write(p):
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("invoice.xls", b"x" * 10)

        with tempfile.TemporaryDirectory() as tmp:
            case = self._case(tmp, write)
            (art,) = collect_artifacts(self._logs(), case)
            self.assertEqual(art["domain"], "evil.example")
            self.assertEqual([e["name"] for e in art["entries"]], ["invoice.xls"])
            self.assertEqual(art["sha256"], hashlib.sha256((case / art["stored_as"]).read_bytes()).hexdigest())
            self.assertEqual(art["time"], "2021-09-24 16:44:40 UTC")

    def test_mime_encoded_attachment_name_is_decoded(self):
        def write(p):
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("a.xls", b"x")

        with tempfile.TemporaryDirectory() as tmp:
            case = self._case(tmp, write)
            (art,) = collect_artifacts(self._logs("=?UTF-8?B?Q2xhaW0uemlw?="), case)
            self.assertEqual(art["name"], "Claim.zip")

    def test_non_archive_has_no_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = self._case(tmp, lambda p: p.write_bytes(b"MZ not a zip"))
            (art,) = collect_artifacts(self._logs(), case)
            self.assertEqual(art["entries"], [])

    def test_no_artifact_folder_gives_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(collect_artifacts(self._logs(), Path(tmp)), [])

    def test_zeek_script_names_the_carved_types(self):
        script = zeek_script()
        self.assertIn('"application/zip"', script)
        self.assertIn("ANALYZER_EXTRACT", script)


def beat(src, dst, times, port=80):
    return [{"id.orig_h": src, "id.resp_h": dst, "id.resp_p": port, "ts": t, "conn_state": "SF"}
            for t in times]


class Beaconing(unittest.TestCase):
    def test_metronome_is_high(self):
        found = detect_beaconing({"conn": beat("10.0.0.5", "45.33.0.5", [i * 30.0 for i in range(20)])})
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")

    def test_beacon_that_sleeps_now_and_then_is_still_seen(self):
        # Regression (real C2 on a capture): steady ~6 s rhythm with long pauses.
        # The standard deviation explodes, the median does not.
        times, t = [], 0.0
        for i in range(40):
            times.append(t)
            t += 70.0 if i % 9 == 8 else 6.0
        found = detect_beaconing({"conn": beat("10.0.0.5", "45.33.0.5", times)})
        self.assertEqual(len(found), 1)

    def test_burst_of_parallel_connections_is_not_a_beacon(self):
        rows = beat("10.0.0.5", "45.33.0.5", [100.0] * 30)
        self.assertEqual(detect_beaconing({"conn": rows}), [])

    def test_irregular_traffic_is_not_a_beacon(self):
        rnd = random.Random(1)
        times, t = [], 0.0
        for _ in range(40):
            t += rnd.uniform(1, 300)
            times.append(t)
        self.assertEqual(detect_beaconing({"conn": beat("10.0.0.5", "45.33.0.5", times)}), [])

    def test_internal_polling_is_ignored(self):
        rows = beat("10.0.0.5", "10.0.0.9", [i * 30.0 for i in range(20)])
        self.assertEqual(detect_beaconing({"conn": rows}), [])


def dns_rec(query, answers, ts=1.0, client="10.0.0.5"):
    return {"id.orig_h": client, "query": query, "answers": answers, "ts": ts, "qtype_name": "A"}


def http_rec(host, server, ts, client="10.0.0.5"):
    return {"id.orig_h": client, "id.resp_h": server, "host": host, "ts": ts, "uid": f"u{ts}"}


class HostMismatch(unittest.TestCase):
    def test_host_claiming_another_site_is_flagged(self):
        # The real pattern: requests say "ocsp.verisign.com" but go to an address
        # that resolved from another name, and that name was never resolved.
        logs = {"dns": [dns_rec("survmeter.example", ["45.33.0.5"])],
                "http": [http_rec("ocsp.verisign.com", "45.33.0.5", t) for t in range(5)]}
        found = detect_host_mismatch(logs)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")
        self.assertEqual(found[0].servers, ["45.33.0.5"])

    def test_medium_when_the_claimed_name_resolves_elsewhere(self):
        logs = {"dns": [dns_rec("survmeter.example", ["45.33.0.5"]),
                        dns_rec("ocsp.verisign.com", ["45.33.0.7"])],
                "http": [http_rec("ocsp.verisign.com", "45.33.0.5", t) for t in range(5)]}
        self.assertEqual(detect_host_mismatch(logs)[0].severity, "medium")

    def test_cname_alias_is_not_a_mismatch(self):
        logs = {"dns": [dns_rec("www.example.com", ["edge.cdn.net", "45.33.0.6"])],
                "http": [http_rec("www.example.com", "45.33.0.6", t) for t in range(5)]}
        self.assertEqual(detect_host_mismatch(logs), [])

    def test_same_site_other_subdomain_is_not_a_mismatch(self):
        logs = {"dns": [dns_rec("www.example.com", ["45.33.0.6"])],
                "http": [http_rec("example.com", "45.33.0.6", t) for t in range(5)]}
        self.assertEqual(detect_host_mismatch(logs), [])

    def test_unresolved_address_is_not_judged(self):
        logs = {"dns": [dns_rec("other.example", ["45.33.0.8"])],
                "http": [http_rec("ocsp.verisign.com", "45.33.0.5", t) for t in range(5)]}
        self.assertEqual(detect_host_mismatch(logs), [])

    def test_a_couple_of_requests_is_not_a_pattern(self):
        logs = {"dns": [dns_rec("survmeter.example", ["45.33.0.5"])],
                "http": [http_rec("ocsp.verisign.com", "45.33.0.5", t) for t in range(2)]}
        self.assertEqual(detect_host_mismatch(logs), [])


def cert(fp, subject, issuer, days=90):
    return {"fingerprint": fp, "certificate.subject": subject, "certificate.issuer": issuer,
            "certificate.not_valid_before": 1_619_000_000.0,  # before the connection below
            "certificate.not_valid_after": 1_619_000_000.0 + days * 86400}


def tls(server, fp, sni=None, port=443, **extra):
    rec = {"ts": 1_620_000_000.0, "id.orig_h": "10.0.0.5", "id.resp_h": server,
           "id.resp_p": port, "server_name": sni, "cert_chain_fps": [fp]}
    rec.update(extra)
    return rec


class SuspiciousTLS(unittest.TestCase):
    def test_self_signed_decade_long_certificate_is_high(self):
        logs = {"ssl": [tls("45.33.0.9", "f1")],
                "x509": [cert("f1", "CN=a.example,O=a", "CN=a.example,O=a", days=3650)]}
        found = detect_suspicious_tls(logs)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")
        self.assertEqual(found[0].servers, ["45.33.0.9"])

    def test_public_ca_with_matching_name_is_clean(self):
        logs = {"ssl": [tls("45.33.0.9", "f1", sni="shop.example", sni_matches_cert=True)],
                "x509": [cert("f1", "CN=shop.example", "CN=R3,O=Let's Encrypt,C=US")]}
        self.assertEqual(detect_suspicious_tls(logs), [])

    def test_no_sni_and_unknown_issuer_is_flagged(self):
        logs = {"ssl": [tls("45.33.0.9", "f1")],
                "x509": [cert("f1", "CN=qwxz.example", "CN=qwxz.example,O=Xyz Inc", days=365)]}
        self.assertEqual(len(detect_suspicious_tls(logs)), 1)

    def test_mail_servers_are_skipped(self):
        logs = {"ssl": [tls("45.33.0.9", "f1", port=25)],
                "x509": [cert("f1", "CN=mx", "CN=mx", days=3650)]}
        self.assertEqual(detect_suspicious_tls(logs), [])

    def test_sni_mismatch_is_flagged(self):
        logs = {"ssl": [tls("45.33.0.9", "f1", sni="bank.example", sni_matches_cert=False)],
                "x509": [cert("f1", "CN=other.example", "CN=R3,O=Let's Encrypt,C=US")]}
        self.assertEqual(len(detect_suspicious_tls(logs)), 1)

    def test_validation_status_still_honoured_when_present(self):
        logs = {"ssl": [{"ts": 1.0, "id.orig_h": "10.0.0.5", "id.resp_h": "45.33.0.9",
                         "id.resp_p": 443, "validation_status": "self signed certificate"}]}
        self.assertEqual(len(detect_suspicious_tls(logs)), 1)

    def test_internal_servers_are_ignored(self):
        logs = {"ssl": [tls("10.0.0.9", "f1")],
                "x509": [cert("f1", "CN=a", "CN=a", days=3650)]}
        self.assertEqual(detect_suspicious_tls(logs), [])


class PostDelivery(unittest.TestCase):
    def _logs(self):
        return {
            "files": [{"source": "HTTP", "is_orig": False, "mime_type": "application/zip",
                       "uid": "u1", "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.4.4", "ts": 1000.0}],
            "http": [{"uid": "u1", "host": "evil.example", "uri": "/a.zip"}],
            "dns": [
                dns_rec("stage2.example", ["45.33.0.1"], ts=1010.0),
                dns_rec("windowsupdate.microsoft.com", ["45.33.0.2"], ts=1011.0),
                {**dns_rec("_ldap._tcp.dc.example", ["dc1.example"], ts=1012.0), "qtype_name": "SRV"},
                dns_rec("evil.example", ["8.8.4.4"], ts=1013.0),
                dns_rec("late.example", ["45.33.0.3"], ts=1000.0 + 400),
                dns_rec("elsewhere.example", ["45.33.0.4"], ts=1020.0, client="10.0.0.99"),
            ],
        }

    def test_lists_only_new_non_platform_names_in_the_window(self):
        (found,) = detect_post_delivery(self._logs())
        self.assertEqual(found.severity, "info")
        self.assertEqual([e.split("] ")[1].split(" ->")[0] for e in found.evidence], ["stage2.example"])

    def test_silent_without_a_download(self):
        logs = self._logs()
        logs["files"] = []
        self.assertEqual(detect_post_delivery(logs), [])


class Indicators(unittest.TestCase):
    def test_profile_of_a_flagged_server(self):
        from pcaptriage.detections.base import Finding

        logs = {
            "dns": [dns_rec("c2.example", ["45.33.0.5"])],
            "http": [{"id.resp_h": "45.33.0.5", "host": "ocsp.verisign.com"}],
            "conn": [{"id.resp_h": "45.33.0.5", "ts": 1632501880.0}],
            "pcaptriage_http": [
                {"resp_h": "45.33.0.5", "name": "SERVER", "value": "LiteSpeed"},
                {"resp_h": "45.33.0.5", "name": "X-POWERED-BY", "value": "PHP/7.2.34"},
            ],
        }
        finding = Finding("beaconing", "t", "high", "d", servers=["45.33.0.5"])
        (ind,) = build_indicators(logs, [finding])
        self.assertEqual(ind["names"], ["c2.example", "ocsp.verisign.com"])
        self.assertEqual((ind["server_header"], ind["powered_by"]), ("LiteSpeed", "PHP/7.2.34"))
        self.assertEqual(ind["first_seen"], "2021-09-24 16:44:40 UTC")
        self.assertEqual(ind["flagged_by"], ["beaconing"])

    def test_nothing_flagged_nothing_listed(self):
        self.assertEqual(build_indicators({"dns": []}, []), [])

    def test_zeek_script_always_logs_server_headers(self):
        self.assertIn("pcaptriage_http", zeek_script(False))
        self.assertNotIn("ANALYZER_EXTRACT", zeek_script(False))
        self.assertIn("ANALYZER_EXTRACT", zeek_script(True))


class Evaluate(unittest.TestCase):
    def test_score_separates_found_missed_and_false_positives(self):
        expected = {"expect": {"beaconing": 2, "dns-tunneling": 1}, "forbid": ["port-scan"]}
        res = score(Counter({"beaconing": 2, "port-scan": 1, "cleartext-services": 3}), expected)
        self.assertEqual(res["found"], {"beaconing": 2})
        self.assertEqual(res["missed"], {"dns-tunneling": {"expected": 1, "found": 0}})
        self.assertEqual(res["false_positives"], {"port-scan": 1})
        self.assertEqual(res["unlisted"], {"cleartext-services": 3})

    def test_fewer_than_expected_counts_as_missed(self):
        res = score(Counter({"beaconing": 1}), {"expect": {"beaconing": 3}})
        self.assertIn("beaconing", res["missed"])


if __name__ == "__main__":
    unittest.main()
