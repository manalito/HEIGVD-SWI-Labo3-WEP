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
from rc4 import RC4

# Cle wep AA:AA:AA:AA:AA
key=b'\xaa\xaa\xaa\xaa\xaa'

# message à chiffrer
plaintext = b"Welcome to lab WEP of SWI"

# Récupération du fichier .cap fourni - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = arp.iv + key

# Calcul du nouvel ICV en effectuant un CRC du message
# l'instruction & 0xffffffff permet de toujours retourner un icv positif
icv = binascii.crc32(plaintext) & 0xffffffff
# Conversion de l'ICV au format int
icv = struct.pack('I', icv)

# Concaténation du message et de l'ICV
plaintext_icv = plaintext + icv

# Calcul du frame body en faisant keystream xor message_clear
cipher = RC4(seed, streaming=False)
cryptedText = cipher.crypt(plaintext_icv)  

# Récupération de l'ICV crypté
icv_crypted=cryptedText[-4:]
(icv_numerique,)=struct.unpack('!L', icv_crypted)

# Récupération du message crypté
text_crypted=cryptedText[:-4] 

# Remplacement du wepData par le message crypté
arp.wepdata = text_crypted

# Remplacement de l'icv par l'icv crypté
arp.icv = icv_numerique

# Affichage de quelques information
print('Text: ' + str(arp.wepdata))
print('icv:  ' + str(icv_crypted))

# Ecriture de la nouvelle trame dans le fichier arp1.cap
wrpcap("arp1.cap", arp)
