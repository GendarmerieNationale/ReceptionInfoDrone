# -*- coding: utf-8 -*

"""
    ##Projet SIE ##

    Version 1 fait en juin-septembre 2019
    Par Gendarmerie Nationnale, STSISI, SIRD

    sniff.py est un processus qui analyse le réseau wifi et envoie les trames Beacon à une file.

"""

# ## IMPORT ## #

# Importation des modules
import lib.scapy.all as scapy

# Librairies natives Python
from multiprocessing import queues


# ## FONCTIONS ## #


def put_in_queue_beacon(queue_beacon_sie, trameBeacon):
    """
        Fonction qui met la trame Beacon dans la file queue_beacon
        et qui supprime le dernier élément en cas de file pleine.
        Ce qui évite de surcharger les files.
    """
    
    try:
        queue_beacon_sie.put_nowait(trameBeacon)

    except queues.Full:
        queue_beacon_sie.get()
        queue_beacon_sie.put(trameBeacon)
        
    if queue_beacon_sie.qsize() == 2900:
        print("queue_beacon pleine ! ")


def sniffer(queue_beacon, interface_wifi):
    """
        Pour l'analyseur réseau, on passe à scapy la fonction "put_in_queue_beacon" en attibut,
        count=0 pour sniffer en permanance,
        et fait un trie sur type 0 et sous-type 8 pour sniffer que les trames Beacon.
        Trie également si le Vendor Sprecific à un OUI/CID et s'il est égal à 6A-5C-35.
    """
    cid = 6970421  # Numéro CID unique pour les drones correspond à 6A-5C-35 en hexa

    scapy.sniff(iface=interface_wifi,
                lfilter=lambda type_subtype: type_subtype.haslayer(scapy.Dot11Beacon) and hasattr(type_subtype[scapy.Dot11EltVendorSpecific], "oui") and type_subtype[scapy.Dot11EltVendorSpecific].oui == cid,                 
                prn=lambda trameBeacon: put_in_queue_beacon(queue_beacon, trameBeacon), count=0, store=False)