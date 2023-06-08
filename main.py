# -*- coding: utf-8 -*-
"""
Created on Sat May  6 12:11:58 2023

@author: Nadav
"""

import ARIA_FUNC as ARIA
import diffie_hellman as ECDH
import elsig_hash as GAMAL


def messageSent(p, a, x, msg):
    s1, s2 = GAMAL.egGen(p, a, x, msg)
    return msg,s1,s2

def messageRecive(p,a,y,s1,s2,msg):
    verify_signature = GAMAL.egVer(p, a, y, s1, s2, msg)
    return msg, verify_signature


def main():
    bits = 256
    #alice private signature key x and public key y
    p, a, x, y = GAMAL.egKey(bits)
    print("Alice generated params for signature")
    print("private x: ", x)
    print("public p, a, y: ", p, a, y)
    #bob private signature key x and public key y
    p2,a2,x2,y2= GAMAL.egKey(bits)
    print("Bob generated params for signature")
    print("private x: ", x2)
    print("public p, a, y: ", p2, a2, y2)

    #ec dh secret keys
    aliceDFSecretKey = ECDH.generateSecretKey(8)
    print("\nAlice generated secret key for DF: ",aliceDFSecretKey)
    bobDFSecretKey = ECDH.generateSecretKey(8)
    print("Bob generated secret key for DF: ", bobDFSecretKey)

    #EC DF public parameters
    F = ECDH.FiniteField(3851, 1)
    # Totally insecure curve: y^2 = x^3 + 324x + 1287(mod 3851)
    curve = ECDH.EllipticCurve(a=F(324), b=F(1287))
    # order is 1964
    basePoint = ECDH.Point(curve, F(920), F(303))


    aliceDFPublicKey = ECDH.sendDH(aliceDFSecretKey, basePoint, lambda x:x)
    print("Alice computed public key for DF: ", aliceDFPublicKey)
    bobDFPublicKey = ECDH.sendDH(bobDFSecretKey, basePoint, lambda x:x)
    print("Bob computed public key for DF: ", bobDFPublicKey)

    #share public keys for EC DF and verify signature
    #alice's part
    msg,s1,s2 = messageSent(p2,a2,x2,bobDFPublicKey)
    print("\nBob sent his DH public key to Alice with a signature: s1=", s1, " s2=", s2)
    bobDFPublicKey, verification = messageRecive(p2, a2, y2, s1, s2, msg)
    if not verification:
        print("bob msg verification failed")
        return 1
    print("Alice has verified Bob's massage")
    #bob's part
    msg, s1, s2 = messageSent(p, a, x, aliceDFPublicKey)
    print("Alice sent her DH public key to Bob with a signature: s1=", s1, " s2=", s2)
    aliceDFPublicKey, verification = messageRecive(p, a, y, s1, s2, msg)
    print("Bob has verified Alice's massage")
    if not verification:
        print("alice msg verification failed")
        return 1

    #create shared key
    sharedSecret = ECDH.receiveDH(bobDFSecretKey, lambda: aliceDFPublicKey)
    print("\nBob compute DF shared key: ", sharedSecret)
    sharedSecret2 = ECDH.receiveDH(aliceDFSecretKey, lambda: bobDFPublicKey)
    print("Alice compute DF shared key: ", sharedSecret)
    sharedKey = sharedSecret.x.n
    sharedKey2 = sharedSecret2.x.n
    if sharedKey != sharedKey2:
        print("shared key failed!")
        return 1
    print("shared key is: {0:0{1}x}\n".format(sharedKey, bits//4))

    #Alice Encryption
    my_string = 'monkey'
    plain = int(my_string.encode('utf-8').hex(), 16)
    cipher = ARIA.ARIA_encryption(plain, sharedKey, bits)
    print("Alice encrypted the massage:",my_string,"With the shared key using ARIA")
    print("Encrypted massage: {0:032x}".format(cipher))

    #Alice send message
    msg, s1, s2 = messageSent(p, a, x, cipher)
    print("\nAlice sent her encrypted massage to Bob with a signature: s1=", s1, " s2=", s2)

    #bob recive message
    aliceCiperRecived, verification = messageRecive(p, a, y, s1, s2, msg)
    if not verification:
        print("alice encrypt msg failed!")
        return 1
    print("Bob has verified Alice's massage")

    
    #Decryption
    decrypted = ARIA.ARIA_decryption(aliceCiperRecived, sharedKey, bits)
    decrypted_str = hex(decrypted)[2:]  # Convert decrypted to hexadecimal string
    original = bytes.fromhex(decrypted_str).decode('utf-8')

    # Print the results

    print("\nBob Decrypted Alice's massage with the shared key: ",original)
    #print("Decrypted text: {0:032x}".format(decrypted))
    #print("original text: ",original)
    
    



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()


