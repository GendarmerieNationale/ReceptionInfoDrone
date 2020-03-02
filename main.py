#!/usr/bin/python3
# -*- coding: utf-8 -*

"""
    ##Projet SIE ##

    Version 1 fait en juin-septembre 2019
    Par Gendarmerie Nationnale, STSISI, SIRD

    main.py contenant le script principal, celui qui appelle les processus indépendants.

"""

# ## IMPORT ## #

# Importation des modules
import lib.sniff
import lib.json

from lib.sh.sh import airmon_ng, service

# Librairies natives Python
import sys
import signal

from multiprocessing import Process, Queue


# ## VARIABLE ## #

# nom de l'interface wifi
interface_wifi = "wlp1s0" 


# ## FONCTIONS ## #


def monitorStart():
    """
        Fonction qui démarre le mode monitor.
    """
    
    print("Mode monitor de l'interface " + interface_wifi)
    try:
        airmon_ng("check", "kill").exit_code == 0
        airmon_ng("start", interface_wifi, 6).exit_code == 0  # 6 correspond au canal wifi
    
    except Exception as err:
        print("impossible de passer en mode monitor, sortie du script ! "+ str(err))
        sys.exit(2)



def monitorStop():
    """
        Fonction qui stoppe le mode monitor et lance l'interface d'origine.
    """

    airmon_ng("stop", interface_wifi).exit_code == 0
    # En fonction de l'OS, permet de relancer les interfaces réseaux
    # service("network-manager", "start").exit_code == 0


def signal_handler(signal, frame):
    """
        Fonction qui stoppe les workers dans l'ordre puis la fonction monitorStop.
    """

    # Arret des workers
    worker_sniffer.terminate()
    worker_json.terminate()
    
    print("\nArret du script.")
    monitorStop()
    
    # Quitte le programme
    sys.exit(0)



#######################################################
#####             Programme principal             #####
#######################################################


# Début du script
print("Lancement du script.")

try:
    # lancement du monitor
    print("Lancement du mode monitor.")
    monitorStart()

except Exception as err:
    print("impossible de passer en mode monitor "+ str(err))
    sys.exit(2)


if __name__ == "__main__":
    """
        Ne se lance que si le script main.py est lancé directement ce qui évite l'import non voulu
        et surtout évite de lancer cette partie du code plusieurs fois. Cela génère des erreurs.
    """
    
    # 'mon' doit être rajouté car sur la plupart des OS linux l'interface en mode monitor prend 'mon' à la fin de son nom. 
    # à vérifier en fonction de l'interface et de l'OS.
    interface_wifi = interface_wifi + "mon"
    
    # Définitions des listes Queue servant pour l'échange de donnée entre les process
    queue_beacon_sie = Queue(maxsize=3000)


    # Définition des workers, les processus indépendant.
    worker_sniffer = Process(target=lib.sniff.sniffer,
                             args=(queue_beacon_sie, interface_wifi, ), name="sniffer")

    worker_json = Process(target=lib.json.verif_and_construction_json,
                          args=(queue_beacon_sie, ), name="json")

    # Lancement des workers
    worker_sniffer.start()
    worker_json.start()

    # Arret des workers avec Ctrl + c
    signal.signal(signal.SIGINT, signal_handler)