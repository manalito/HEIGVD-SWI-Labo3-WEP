#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#  Authors : Yimnaing Kamdem && Siu Aurelien
#  Objectif: Développer un script en Python/Scapy capable de chiffrer un message, l’enregistrer
#            dans un fichier pcap et l’envoyer. Vous devrez donc créer votre message, calculer 
#            le contrôle d’intégrité (ICV).
#
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

from scapy.all import *
import binascii
import rc4


#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

#Lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient
arp = rdpcap('arp.cap')[0]

#message à crypter 
plaintext = "Welcome to lab WEP of SWI"


#rc4 seed est composé de IV+clé
seed = arp.iv+key

#Calcul de l'ICV du plaintext
icv = binascii.crc32(plaintext) & 0xffffffff

#Conversion de l'icv en format int 
icv = struct.pack('I', icv)

#Concaténation du message et de l'ICV
plaintext = plaintext + icv

# Calcul du frame body en faisant keystream xor message_clear
cipher= rc4.rc4crypt(plaintext, seed)

#Remplacement des champs wepdata par le message crypté et de l'icv
arp.wepdata = cipher[:-4]
(arp.icv,) = struct.unpack("!L", cipher[-4:])


# Affichage de quelques information
print 'Text: ' + arp.wepdata.encode("hex")
print 'icv:  ' + icv.encode("hex")

#Ecriture de la nouvelle trame dans le fichier arp1.cap
wrpcap('arp1.cap', arp)
