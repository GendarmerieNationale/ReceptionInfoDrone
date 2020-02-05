**
			##Projet SIE ##

Version 1 fait en juin-septembre 2019 
Par Gendarmerie Nationnale, STSISI, SIRD.

BUT : Récupérer les trames Beacon émises par les drones, les réceptionnées,
les décodées.

Fait en multiprocessing afin d’optimiser les performances et sniffer le réseau en permanance.
Utilisation de Queue pour partager l'information entre les Process.

Les librairies non-natives à Python sont déjà dans le projet, dossier « lib ». Vérifier qu’il n’y a pas de doublon installer sur le poste.
Si c’est le cas, désinstaller ces librairies afin que le projet fonctionne correctement.

Lancer le script main.py en root.

Besoin pour fonctionner d'installer le paquet aircrack-ng
$ sudo apt install aircrack-ng

Une variable "interface_wifi" permet de définir le nom de l'interface wifi sur laquelle le mode monitor sera activé.
Le mode monitor fonctionne sur le canal wifi 6 (2,437 GHz) prévu dans l'arrêté.



**



