# -*- coding: utf-8 -*

"""
    ##Projet SIE ##

    Version 1 fait en juin-septembre 2019
    Par Gendarmerie Nationnale, STSISI, SIRD

    json.py est un processus qui décode les trames Beacon drones, surtout le Vendor Specific avec le mécanisme TLV.
    Après cela, il crée un JSON.

"""

# ## IMPORT ## #

# Importation des modules
import lib.scapy.all as scapy

from lib.sh.sh import service

# Librairies natives Python
import json

from multiprocessing import queues
from struct import *


# ## FONCTIONS ## #


def verif_and_construction_json(queue_beacon_sie):
    """
        Fonction qui vérifie ID et le protocole,
        puis décode le TLV.
        Consrtuit après un JSON.
    """

    vs_protocole = b'\x01'   # vs_type du protocole fixé à 0x01 en binaire

    while True:
        
        trame = queue_beacon_sie.get()

        vs_type = (trame[scapy.Dot11EltVendorSpecific].info[3:4])     # vs_type de la trame
        
        dataDict = {}
        data = trame[scapy.Dot11EltVendorSpecific].info[1:]
        
        try:
            if vs_type == vs_protocole and len(str(trame[scapy.Dot11EltVendorSpecific].info)) > 30: # taille minimale de la trame

                t = 0
                l = 0
                v = ""

                for i in data:
                    try:
                        t = ord(data[0:1])
                        l = ord(data[1:2])
                        hopl = 2 + l

                    except TypeError as err:
                        break

                    try:
                        if t == 2 or t == 3:
                            """
                                Conversion bytes vers string.
                                Type 2 pour l'identifiant FR sur 30 caractères.
                                Type 3 pour l'identifiant ANSI.
                            """
                            v = str(data[2:hopl], "utf-8")
                            data = data[hopl:]

                        elif t == 4 or t == 5 or t == 8 or t == 9:
                            """
                                Conversion bytes vers float avec présicion de 5 chiffres apres la virgule.
                                On récupère la data en Bytes on la passe en int signé.
                                type 4 et 5 pour latitude et longitude.
                                type 8 et 9 pour latitude de départ et longitude de départ.
                            """
                            v = float(int.from_bytes(data[2:hopl], byteorder="big", signed=True))/100000
                            data = data[hopl:]

                        elif t == 6 or t == 7:
                            """
                                Conversion bytes vers int.
                                On récupère la data en Bytes on la passe en int signé
                                Type 6 et 7 pour l'altitude et hauteur courante.
                            """
                            v = int.from_bytes(data[2:hopl], byteorder="big", signed=True)
                            data = data[hopl:]

                        elif t == 10 or t == 11 or t == 1:
                            """
                                Conversion bytes vers int.
                                On récupère la data en Bytes on la passe en int  non signé
                                Type 10 et 11 pour la vitesse et la direction en degrés.
                            """
                            v = int.from_bytes(data[2:hopl], byteorder="big", signed=False)
                            data = data[hopl:]

                    except TypeError as err:
                        print(err)
                        break

                    """
                        Ajout des informations dans un dictionnaire.
                    """
                    dataDict.update({t : v})
                
                # création du JSON grâce au dictionnaire
                dataJSON = json.dumps(dataDict, separators=(',', ':'))
                print("JSON du drone : ", dataJSON)
                """
                JSON généré correspondant à l'arrêté du 27 décembre 2019
                1 : Version du protocole
                2 : Identifiant FR sur 30 caractères
                3 : Identifiant ANSI CTA 2063 UAS (numéro de série physique - PSN)
                4 : Latitude courante aéronef (signée)
                5 : Longitude courante aéronef (signée)
                6 : Altitude courante aéronef (signée)
                7 : Hauteur courante aéronef (signée)
                8 : Latitude point de décollage (signée)
                9 : Longitude point de décollage (signée)
                10 : Vitesse horizontale
                11 : Route vraie
                """
                
        
        except AttributeError as err:
            print(err)
            pass
        except TypeError as err:
            print(err)
            pass