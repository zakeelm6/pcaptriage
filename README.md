# pcaptriage

[![PyPI](https://img.shields.io/pypi/v/pcaptriage.svg)](https://pypi.org/project/pcaptriage/)
[![Python](https://img.shields.io/pypi/pyversions/pcaptriage.svg)](https://pypi.org/project/pcaptriage/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Triage automatique de captures reseau, construit au-dessus de **Zeek**.

Wireshark est manuel : tu ouvres un pcap et tu cherches toi-meme. pcaptriage
fait l'inverse. Il laisse Zeek parser les protocoles, puis il applique une
couche de triage : il detecte des comportements suspects, les mappe sur
**MITRE ATT&CK**, et sort un rapport HTML priorise plus un JSON automatisable.
Pensé pour traiter un pcap (ou un dossier entier) en une commande et rendre un
verdict lisible, pas pour remplacer le decodeur de Wireshark.

![Exemple de rapport pcaptriage](docs/report.jpg)

*Exemple de rapport : findings priorises par severite, chacun mappe sur MITRE ATT&CK.*

## Ce qu'il detecte

| Detection | Signal | MITRE |
|---|---|---|
| Credentials en clair | FTP/HTTP basic auth, services non chiffres | T1552, T1040 |
| Scan de ports / hotes | une source touche beaucoup de ports/hotes, connexions non abouties | T1046 |
| DNS tunneling / exfiltration | fort volume + noms longs/haute entropie vers un domaine | T1071.004, T1048 |
| Beaconing / C2 | rappels a intervalle quasi constant vers une meme destination | T1071, T1095 |
| Certificats TLS suspects | certificats auto-signes, expires ou non valides | T1573 |
| Poisoning LLMNR/NBT-NS/mDNS | un hote repond aux requetes de resolution de noms de plusieurs victimes (style Responder) | T1557.001 |

## Prerequis

- **Python 3.9+** (teste sur 3.14). Aucune dependance pip, stdlib uniquement.
- **Zeek**, au choix :
  - local : `zeek` dans le PATH ;
  - **Docker** (recommande sur Kali, ou le paquet .deb casse la libc) :
    ```bash
    docker pull zeek/zeek:lts
    ```

## Installation

```bash
# depuis PyPI (recommande)
pip install pcaptriage
# ou, pour une commande systeme isolee
pipx install pcaptriage

# en developpement, depuis une copie locale
pip install -e .
```

Une fois installe, la commande `pcaptriage` est disponible. Sans installation,
tout marche aussi via `python3 -m pcaptriage`.

## Usage

```bash
# un seul pcap, Zeek via Docker
pcaptriage capture.pcap --docker

# un dossier entier de captures
python3 -m pcaptriage ./captures/ --docker -o resultats/

# Zeek installe en local
python3 -m pcaptriage capture.pcap
```

Sortie, par capture, dans le dossier `-o` (defaut `pcaptriage-report/`) :

```
pcaptriage-report/
  <nom-capture>/
    report.html      <- rapport lisible (clair/sombre), findings prioritises
    findings.json    <- meme contenu, automatisable (injectable dans un SIEM)
    zeek-logs/       <- logs Zeek bruts (conn/dns/http/ssl/...)
```

## Architecture

```
pcap --> Zeek (parsing) --> *.log JSON --> loader --> detections --> findings
                                                          |             |
                                                      MITRE map     report HTML + JSON
```

- `zeek_runner.py` lance Zeek (local ou Docker) et produit les logs JSON.
- `loader.py` charge les logs en memoire.
- `detections/` : une detection = une fonction decoree `@register` qui prend
  les logs et renvoie des `Finding`. Ajouter une detection = ajouter un fichier.
- `mitre.py` : table technique -> (nom, lien).
- `report.py` : resume de la capture + rendu HTML autonome.
- `cli.py` : orchestration, mode fichier ou dossier.

## Feuille de route

- ARP spoofing / MITM, LLMNR/NBT-NS poisoning
- Extraction de fichiers (files.log) et de credentials additionnels
- Moteur de regles externes (YAML/Sigma-like) pour etendre sans coder
- Graphe de communication dans le rapport
- Sortie directe vers Elasticsearch (lien avec Mini-SOC)

## Note

Outil d'analyse defensive / forensic sur des captures que tu es autorise a
analyser. Les logs peuvent contenir des donnees sensibles (identifiants,
hotes) : traite les sorties en consequence.
