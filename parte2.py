'''
Maria Jose Castro 181202
Diana de Leon 18607
Camila Gonzalez 18398
Maria Ines Vasquez 18250
'''

# Codigo Refrenciado https://cryptobook.nakov.com/digital-firmas/rsa-sign-verify-examples

from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii

# Generar la llave pública y privada utilizando RSA
llaves = RSA.generate(bits=1024)
print(f"La llave publica es: \n n={hex(llaves.n)} \n e={hex(llaves.e)} \n")

print(f"La llave privada es: \n n={hex(llaves.n)} \n d={hex(llaves.d)} \n")
llavepublica = llaves.publickey()

# Este es el mensaje a firmar
mensaje = b'Hola, este es el mensaje a firmar'

# Se aplica un hash al mensaje
hash = SHA256.new(mensaje)

# Se firma utilizando el estandar de RSA -> PKCS#1
firmador = PKCS115_SigScheme(llaves)
firma = firmador.sign(hash)

print("La firma es: \n", binascii.hexlify(firma), "\n")

# Verificar una firma válida
mensaje = b'Hola, este es el mensaje a firmar'
hash = SHA256.new(mensaje)
verificador = PKCS115_SigScheme(llavepublica)

print("Verificar firma con el mensaje correcto \n")

try:
    # Si es correcto nos dice que la fima es valida
    verificador.verify(hash, firma)
    print("La firma es valida \n")
except:
    # Si no nos dice que hay un error sin dar mayor información
    print("La llave es invalida o el texto ha sido modificado \n")

# Verificar utilizando una firma diferente
mensaje = b'Un mensaje totalmente distinto al real'
hash = SHA256.new(mensaje)
verificador = PKCS115_SigScheme(llavepublica)

print("Verificar firma con un mensaje distinto \n")

try:
    # Si es correcto nos dice que la fima es valida
    verificador.verify(hash, firma)
    print("La firma es valida \n")
except:
    # Si no nos dice que hay un error sin dar mayor información
    print("La llave es invalida o el texto ha sido modificado \n")