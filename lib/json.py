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

# Librairies natives Python
import json
import time

from multiprocessing import queues
from struct import *


# ## FONCTIONS ## #
list_wifi = {2412:1, 2417:2, 2422:3, 2427:4, 2432:5, 2437:6, 2442:7,
                    2447:8, 2452:9, 2457:10, 2462:11, 2467:12, 2472:13, 2484:14
                    }

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

        frequency = trame.Channel
        channel = list_wifi[frequency]
        rssi = trame.dBm_AntSignal
        timeStamp_trame = int(trame.time)
        
        try:
            if vs_type == vs_protocole and len(str(trame[scapy.Dot11EltVendorSpecific].info)) > 30: # taille minimale de la trame

                t = 0
                l = 0
                v = ""

                for i in data:
                    if len(str(data)) > 3:

                        try:
                            t = ord(data[0:1])
                            l = ord(data[1:2])
                            hopl = 2 + l

                        except TypeError as err:
                            print("erreur ", err)
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
                            print("erreur 2 ", err)
                            break

                        """
                            Ajout des informations dans un dictionnaire.
                        """
                        dataDict.update({t : v})

                dataDict.update({201: timeStamp_trame})
                dataDict.update({202: int(time.time())})
                dataDict.update({203: channel})
                dataDict.update({204: rssi})
                
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
