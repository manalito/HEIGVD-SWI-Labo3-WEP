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
key=b'\xaa\xaa\xaa\xaa\xaa'

def rc4(s, val):
    l = len(val)
    buf = bytearray(l)
    i = 0
    j = 0
    idx = 0
    while idx < l:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xff]
        buf[idx] = (ord(val[idx])) ^ k
        idx = idx + 1
    return str(buf)

# Lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient
arp = rdpcap('arp.cap')[0]

# message à chiffrer
plaintext = "Welcome to lab WEP of SWI"

# rc4 seed est composé de IV+clé
seed = arp.iv + key

# Calcul de l'ICV du plaintext
icv = binascii.crc32(plaintext.encode()) & 0xffffffff

# Conversion de l'icv en format int 
icv = struct.pack('I', icv)


# Concaténation du message et de l'ICV
plaintext1 = plaintext + str(icv)

# Calcul du frame body en faisant keystream xor message_clear
cipher= rc4(seed, plaintext1)

#Remplacement des champs wepdata par le message crypté et de l'icv
arp.wepdata = cipher[:-4]
(arp.icv,) = struct.unpack("!L", cipher[-4:])


# Affichage de quelques information
print ('Text: ' + arp.wepdata.encode("hex"))
print ('icv:  ' + icv.encode("hex"))

#Ecriture de la nouvelle trame dans le fichier arp1.cap
wrpcap('arp1.cap', arp)
