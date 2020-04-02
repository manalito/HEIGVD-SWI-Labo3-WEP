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
import rc4 import RC4


#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

#Lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient
arp0 = rdpcap('arp.cap')[0]
arp1 = rdpcap('arp.cap')[0]
arp2 = rdpcap('arp.cap')[0]

#message à crypter 
plaintext0 = "Welcome to lab WEP of SWI. "
plaintext1 = "Task 3 manual encryption fragmentation. "
plaintext2 = "This is the last fragment"


#rc4 seed est composé de IV+clé
seed0 = arp0.iv+key
seed1 = arp1.iv+key
seed2 = arp2.iv+key

#Calcul de l'ICV du plaintext
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
icv_crypted0=cryptedText0[-4:]
(icv_numerique0,)=struct.unpack('!L', icv_crypted0)

icv_crypted1=cryptedText1[-4:]
(icv_numerique1,)=struct.unpack('!L', icv_crypted1)

icv_crypted2=cryptedText2[-4:]
(icv_numerique2,)=struct.unpack('!L', icv_crypted2)

# Récupération du message crypté
text_crypted0 = cryptedText0[:-4] 
text_crypted1 = cryptedText1[:-4] 
text_crypted2 = cryptedText2[:-4] 

#Remplacement des champs wepdata par le message crypté et de l'icv
arp0.wepdata = cipher0[:-4]
(arp0.icv,)  = icv_numerique0

arp1.wepdata = cipher1[:-4]
(arp1.icv,)  = icv_numerique1

arp2.wepdata = cipher2[:-4]
(arp2.icv,)  = icv_numerique2

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

# Concaténation des trames
arp = []
arp.append(arp0)
arp.append(arp1)
arp.append(arp2)

#Ecriture de la nouvelle trame dans le fichier arp1.cap
wrpcap('arp2.cap', arp)