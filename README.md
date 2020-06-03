# Projet SIE

*Version 1 fait en juin-septembre 2019 Par Gendarmerie Nationale, STSISI, SIRD.*

## BUT : Récupérer les trames Beacon émises par les drones ou par un dispositif de signalement électronique, les décoder, les afficher.

Fait en multiprocessing afin d’optimiser les performances et sniffer le réseau en permanence.

Utilisation de « queue » pour partager l'information entre les différents process.


Nous n'assurons pas un fonctionnement avec d'autre version de dépendance que celle décrite après.

Voici le détail des versions de nos tests :

Sur poste de travail :
- OS : Linux Ubuntu 18.04, noyau 4.15.0-52-generic
- Architecture : amd 64
- Wifi : chipset wifi doit pouvoir basculer en monitoring avec airmon-ng
	
Sur raspberry 3 ou 4 :
- OS : Raspbian Buster Lite 2019-07-10, noyau 4.19 
- Architecture : arm 64
- Wifi : Alfa network awus036acs

Pour poste de travail et raspberry :
- Python : 3.6.8
- Aircrack-ng : 1.2


Les autres dépendances sont présentes dans le projet, et il faut les utiliser (comme par exemple pour scapy : uniquement la version modifiée du projet).

Pour être certain de ne pas utiliser une autre version de dépendance, utiliser un environnement virtuel ou désinstaller les librairies présentes sur le poste afin que le projet fonctionne correctement.


Lancer le script main.py en **root**.


Une variable "interface_wifi" permet de définir le nom de l'interface wifi sur laquelle le mode monitor sera activé. 

Le mode monitor est lancé sur le canal wifi 6 (2,437 GHz) prévu dans l'arrêté.
