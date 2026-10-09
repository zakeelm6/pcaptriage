"""Regression tests for the detections, on small synthetic Zeek logs.

Run with:  python -m unittest discover -s tests

Each false positive found on a real capture gets a test here, so a later
change to a threshold cannot silently bring it back.
"""

import base64
import codecs
import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from pcaptriage.artifacts import collect_artifacts, zeek_script

from pcaptriage.correlation import build_narrative
from pcaptriage.decode import decode_findings
from pcaptriage.detections.mass_mailing import detect_mass_mailing
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


if __name__ == "__main__":
    unittest.main()
