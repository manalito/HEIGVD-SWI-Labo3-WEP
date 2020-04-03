#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#  Authors : Yimnaing Kamdem && Siu Aurelien
#  Objectif: Développer un script en Python/Scapy en enrichirissisant notre script développé 
#			 dans la partie précédente pour chiffrer 3 fragments.
#
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

from scapy.all import *
import binascii
from rc4 import RC4


# Cle wep AA:AA:AA:AA:AA
key=b'\xaa\xaa\xaa\xaa\xaa'

# Message à crypter 
plaintext0 = b"Welcome to lab WEP of SWI. "
plaintext1 = b"Task 3 manual encryption fragmentation. "
plaintext2 = b"This is the last fragment"

# Lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient
arp0 = rdpcap('arp.cap')[0]
arp1 = rdpcap('arp.cap')[0]
arp2 = rdpcap('arp.cap')[0]

# Rc4 seed est composé de IV+clé
seed0 = arp0.iv + key
seed1 = arp1.iv+key
seed2 = arp2.iv+key

# Calcul de l'ICV du plaintext
icv0 = binascii.crc32(plaintext0) & 0xffffffff
icv1 = binascii.crc32(plaintext1) & 0xffffffff
icv2 = binascii.crc32(plaintext2) & 0xffffffff

#Conversion de l'icv en format int 
icv0 = struct.pack('I', icv0)
icv1 = struct.pack('I', icv1)
icv2 = struct.pack('I', icv2)

#Concaténation du message et de l'ICV
plaintext_icv0 = plaintext0 + icv0
plaintext_icv1 = plaintext1 + icv1
plaintext_icv2 = plaintext2 + icv2

# Calcul du frame body en faisant keystream xor message_clear
cipher0 = RC4(seed0, streaming=False)
cryptedText0 = cipher0.crypt(plaintext_icv0) 

cipher1 = RC4(seed1, streaming=False)
cryptedText1 = cipher1.crypt(plaintext_icv1) 

cipher2 = RC4(seed2, streaming=False)
cryptedText2 = cipher2.crypt(plaintext_icv2) 

# Récupération de l'ICV crypté 
icv0_crypted=cryptedText0[-4:]
(icv0_numerique,)=struct.unpack('!L', icv0_crypted)

icv1_crypted=cryptedText1[-4:]
(icv1_numerique,)=struct.unpack('!L', icv1_crypted)

icv2_crypted=cryptedText2[-4:]
(icv2_numerique,)=struct.unpack('!L', icv2_crypted)

# Récupération du message crypté
text_crypted0 = cryptedText0[:-4] 
text_crypted1 = cryptedText1[:-4] 
text_crypted2 = cryptedText2[:-4] 

#Remplacement des champs wepdata par le message crypté et de l'icv
arp0.wepdata = text_crypted0
arp0.icv  = icv0_numerique

arp1.wepdata = text_crypted1
arp1.icv = icv1_numerique

arp2.wepdata = text_crypted2
arp2.icv  = icv2_numerique

#Activation du bit More fragment de la première trame
arp0.FCfield.MF = True

#Activation du bit More fragment de la deuxième trame
arp1.FCfield.MF = True

#Incrémentation du compteur de fragment
arp1.SC += 1

#Désactivation du bit More fragment de la dernière trame
arp2.FCfield.MF = False

#Incrémentation du compteur de fragment
arp2.SC += 2

# Affichage de quelques information
print('Texte 1 en clair : ' + str(plaintext0.hex()))
print('Texte 1          : ' + str(arp0.wepdata.hex()))
print('icv 1 (chiffré)  : ' + str(icv0_crypted.hex()))

print('Texte 2 en clair : ' + str(plaintext1.hex()))
print('Texte 2          : ' + str(arp1.wepdata.hex()))
print('icv 2 (chiffré)  : ' + str(icv1_crypted.hex()))

print('Texte 3 en clair : ' + str(plaintext2.hex()))
print('Texte 3          : ' + str(arp2.wepdata.hex()))
print('icv 3 (chiffré)  : ' + str(icv2_crypted.hex()))

# permet de reformer correctement les paquets
# -> scapy recalcule la bonne taille
arp0[RadioTap].len = None
arp1[RadioTap].len = None 
arp2[RadioTap].len = None

# Concaténation des trames
arp = []
arp.append(arp0)
arp.append(arp1)
arp.append(arp2)

# Ecriture de la nouvelle trame dans le fichier arp3.cap
wrpcap("arp3.cap", arp)
