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
        Fonction qui met la trame Beacon du drone dans la file queue_beacon_sie
        et qui supprime le dernier élément en cas de file pleine.
        Ce qui évite de surcharger les files.
        Trie également si le Vendor Sprecific à un OUI/CID et s'il est égal à 6A-5C-35.
    """
    cid = 6970421  # Numéro CID unique pour les drones correspond à 6A-5C-35 en hexa
    
    for payloads in trameBeacon.iterpayloads(): # parcours les différents VS
        if hasattr(payloads[scapy.Dot11Elt], "oui"):  # présence de OUI/CID
            if payloads[scapy.Dot11EltVendorSpecific].oui == cid:  # vérification de l'OUI conforme avec l'arrêté
                trameBeacon[scapy.Dot11EltVendorSpecific] = payloads[scapy.Dot11EltVendorSpecific]
                
                try:
                    queue_beacon_sie.put_nowait(trameBeacon)
                    # print("beacon_sie", queue_beacon_sie.qsize())

                except queues.Full:
                    queue_beacon_sie.get()
                    queue_beacon_sie.put(trameBeacon)
                    
                if queue_beacon_sie.qsize() == 2900:
                    print("queue_beacon pleine ! ")
                break


def sniffer(queue_beacon, interface_wifi):
    """
        Pour l'analyseur réseau, on passe à scapy la fonction "put_in_queue_beacon" en attibut,
        count=0 pour sniffer en permanance,
        et fait un trie sur type 0 et sous-type 8 pour sniffer que les trames Beacon.
    """

    scapy.sniff(iface=interface_wifi,
                lfilter=lambda type_subtype: type_subtype.haslayer(scapy.Dot11Beacon) and type_subtype.haslayer(scapy.Dot11EltVendorSpecific),           
                prn=lambda trameBeacon: put_in_queue_beacon(queue_beacon, trameBeacon), count=0, store=False)