# Validation sur une capture reelle

Jusqu'a la v0.3.0, pcaptriage n'avait ete teste que sur des captures fabriquees
a la main. Ce document decrit le premier test sur une vraie infection, ce qu'il a
revele, et ce qu'il ne prouve pas.

## Methode

- **Capture** : une infection reelle (document Office piege, balise C2, spam
  sortant), issue d'un lab public de forensique reseau. Le pcap n'est pas
  redistribue ici, et ce document ne contient ni adresse, ni domaine, ni reponse
  du lab, pour ne rien spoiler.
- **Verite de terrain** : etablie en lisant moi-meme les logs Zeek bruts
  (`http.log`, `files.log`, `smtp.log`, `conn.log`). Ce n'est **pas** un corrige
  officiel.
- **Procedure** : lancer l'outil, comparer a la verite de terrain, corriger ce
  qui est faux, ecrire un test de non-regression pour chaque faux positif.

## Resultats

| Comportement present dans la capture | 1er passage (v0.3.0) | Apres corrections |
|---|---|---|
| Archive ZIP telechargee en HTTP depuis un domaine externe | **manque** | detecte (`suspicious-download`) |
| Balise HTTP reguliere (26 requetes, intervalle ~25 s) | detecte | detecte |
| Spam sortant : 41 sessions SMTP vers 26 serveurs, 3 archives ZIP jointes | **manque** | detecte (`mass-mailing`) |
| Recit d'attaque sur le poste infecte | Reconnaissance + C2 (faux) | **Delivery > C2 > Propagation** |

Avec `--artifacts`, l'outil fournit en plus, sans rien extraire des archives :
l'heure de reception de l'archive, son nom, son domaine d'origine, son SHA-256
et la liste des fichiers qu'elle contient. Les trois archives envoyees par mail
sont inventoriees de la meme facon.

## Faux positifs du 1er passage, corriges

1. **« Scan de ports » sur un poste ordinaire.** La regle comptait le nombre
   d'hotes distincts contactes (seuil 25). Un poste qui parle a des dizaines de
   serveurs web depasse ce seuil sans scanner quoi que ce soit. Corrige : un
   balayage exige maintenant que la majorite des connexions vers ce port
   n'aboutissent pas (>= 70 %).
2. **Decodage ROT13 qui remontait du charabia.** Le ROT13 d'un texte lisible
   ressemble toujours a du texte, donc le filtre anti-bruit le validait. Corrige :
   un ROT13 n'est remonte que s'il revele un mot-cle sensible (flag, commande,
   identifiant).

Chacun a un test dans `tests/test_detections.py`.

## Ce que cela ne prouve pas

- **Une seule capture.** Ce n'est pas un benchmark.
- **Les seuils ont ete ajustes sur cette capture.** Les resultats ci-dessus sont
  donc optimistes : une detection reglee sur un exemple ressemble a de la
  memorisation tant qu'elle n'a pas ete confirmee sur des captures jamais vues.
- **Pas de mesure de rappel.** On sait ce qui a ete trouve parmi ce que j'ai
  repere a la main, pas ce qu'une capture contient d'autre.
- **Trafic chiffre.** Le contenu TLS reste invisible sans fichier de cles.

## Suite

Rejouer l'outil sur des captures jamais vues (CTU-13, exercices publics de
malware-traffic-analysis.net), sans toucher aux seuils avant la mesure, puis
publier les resultats bruts, y compris les echecs.
