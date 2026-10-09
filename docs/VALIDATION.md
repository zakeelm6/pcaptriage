# Validation sur une capture reelle

Jusqu'a la v0.3.0, pcaptriage n'avait ete teste que sur des captures fabriquees
a la main. Ce document decrit deux tours de test sur une vraie infection, ce
qu'ils ont revele, et ce qu'ils ne prouvent pas.

## Methode

- **Capture** : une infection reelle (document Office piege, balises C2 en HTTP
  et en HTTPS, spam sortant), issue d'un lab public de forensique reseau. Le pcap
  n'est pas redistribue, et ce document ne contient ni adresse, ni domaine, ni
  reponse du lab, pour ne rien spoiler.
- **Verite de terrain** : etablie en lisant moi-meme les logs Zeek bruts
  (`http.log`, `files.log`, `smtp.log`, `conn.log`, `dns.log`, `x509.log`). Au
  second tour, les serveurs C2 ont aussi ete recoupes avec les rapports publics de
  VirusTotal (detections des editeurs et commentaires de la communaute). Ce n'est
  **pas** un corrige officiel, et les commentaires de la communaute ne sont pas
  verifies (l'un d'eux affirme meme « ce n'est pas un C2 »).
- **Procedure** : lancer l'outil, comparer a la verite de terrain, corriger ce
  qui est faux, ecrire un test de non-regression pour chaque erreur.

## Tour 1 (v0.3.0)

| Comportement present dans la capture | Resultat |
|---|---|
| Archive ZIP telechargee en HTTP depuis un domaine externe | **manque** |
| Balise HTTP reguliere (26 requetes, ~25 s) | detecte |
| Spam sortant : 41 sessions SMTP vers 26 serveurs, 3 archives ZIP jointes | **manque** |
| « Scan de ports » sur le poste infecte | **faux positif** (seuil sur le nombre d'hotes) |
| Decodage ROT13 | **bruit** (le filtre validait du charabia) |

Corrections : detections `suspicious-download` et `mass-mailing`, un balayage
exige maintenant que la majorite des connexions n'aboutissent pas, un ROT13 n'est
remonte que s'il revele un mot-cle.

## Tour 2 : recoupement avec une source externe

Verifier les adresses sur VirusTotal et relire les logs a revele quatre problemes
que le tour 1 n'avait pas vus :

1. **Deux des trois serveurs de balisage etaient manques** (les deux que les
   rapports VirusTotal rattachent a Cobalt Strike ; le troisieme est retenu pour
   son seul comportement, sans confirmation externe). Ils emettent des balises avec
   de longues pauses : l'ecart-type des intervalles explose (CV de 1,1 a 1,3) alors
   que leur **mediane** est tres stable (MAD/mediane de 0,01 a 0,09). Le test
   existant ne regardait que l'ecart-type. Corrige : un second test sur la
   mediane, avec une mediane minimale de 1 s pour ecarter les rafales de
   connexions paralleles.
2. **Usurpation de l'en-tete `Host`.** 76 requetes annoncant le nom d'un service de
   certificats partaient vers une adresse resolue depuis un tout autre domaine, qui
   n'avait jamais ete resolu. Aucune detection ne le voyait. Nouvelle detection
   `http-host-mismatch`.
3. **La detection TLS ne pouvait pas se declencher sur un vrai pcap.** Elle lisait
   des champs (`validation_status`, `subject`, `issuer`) que Zeek n'ecrit dans
   `ssl.log` que si une politique optionnelle est chargee. Elle n'avait jamais
   fonctionne que sur mes logs synthetiques. Reecrite pour joindre `ssl.log` et
   `x509.log` par empreinte. Elle signale desormais deux serveurs que VirusTotal
   classe malveillants (13 puis 7 editeurs sur 92), et ignore les serveurs de
   messagerie.
4. **Une erreur de ma part** : un module ajoute pendant ce tour (`post_delivery`)
   plantait sur une constante mal nommee. Aucun test ne le couvrait, je ne l'ai vu
   qu'en rejouant la capture entiere. Il a maintenant des tests, et cela rappelle
   que les tests unitaires ne remplacent pas l'essai sur une vraie capture.

## Resultat actuel

`python -m pcaptriage.evaluate --expected validation/carnage.expected.json --logs ...`

| Comportement | Detecte par |
|---|---|
| Archive ZIP telechargee en HTTP | `suspicious-download` |
| 3 serveurs de balisage (2 en HTTP, 1 en HTTPS) | `beaconing` x3 |
| Requetes qui se font passer pour un service de certificats | `http-host-mismatch` |
| Serveurs TLS a certificat auto-signe ou sans SNI/emetteur connu | `suspicious-tls` |
| Spam sortant avec archives jointes | `mass-mailing` |
| Aucun faux positif parmi : scan, DNS tunneling, creds en clair, poisoning, decodage | |

Le recit d'attaque du poste infecte est **Delivery > Command & Control > Propagation**.
Avec `--artifacts`, l'outil donne aussi le nom, le domaine d'origine, l'heure, le
SHA-256 et le contenu (index seulement) des archives, et le tableau « Flagged
servers » donne le logiciel serveur et le certificat de chaque adresse signalee.

## Ce que cela ne prouve pas

- **Le resultat est circulaire.** Les seuils ont ete corriges en regardant cette
  meme capture. `evaluate` repond OK parce que j'ai fait en sorte qu'il reponde OK.
  Cela montre que les corrections marchent, pas que l'outil generalise.
- **Une seule capture, ce n'est pas un benchmark.** Aucun taux de rappel : on sait
  ce qui a ete trouve parmi ce que j'ai repere, pas ce que la capture contient en
  plus.
- **Les nouvelles regles peuvent faire des faux positifs ailleurs.** Un poll
  periodique legitime vers un serveur externe ressemble a une balise ; un site qui
  repond sur plusieurs noms peut ressembler a une usurpation de `Host`. Rien ne le
  mesure encore.
- **La liste de domaines de plateforme** des « contacts apres livraison » est
  ecrite a la main et forcement incomplete. Cette section est du contexte, pas un
  verdict : elle ne sait pas dire qu'un domaine est malveillant.
- **Trafic chiffre.** Le contenu TLS reste invisible sans fichier de cles. Les
  telechargements de seconde etape en HTTPS ne sont donc pas detectes, seulement
  signales par leur proximite dans le temps avec la livraison.

## Suite

Rejouer l'outil sur des captures jamais vues (CTU-13, exercices publics de
malware-traffic-analysis.net), **sans toucher aux seuils avant la mesure**, puis
publier les resultats bruts, y compris les echecs. C'est la seule facon de sortir
du raisonnement circulaire.
