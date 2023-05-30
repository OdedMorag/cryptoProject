# -*- coding: utf-8 -*-
"""
Created on Sat May  6 12:11:58 2023

@author: Nadav
"""

import ARIA_FUNC as ARIA
import diffie_hellman as ECDH
import elsig_hash as GAMAL

def main():
    

    my_string = 'monkey'
    plain = int(my_string.encode('utf-8').hex(), 16)
    print("\n\nPlain text: ",my_string)

    
    #ECDH:
    print("\nElliptic Curve D-H:\n")
    F = ECDH.FiniteField(3851, 1)
    # Totally insecure curve: y^2 = x^3 + 324x + 1287
    curve = ECDH.EllipticCurve(a=F(324), b=F(1287))
    # order is 1964
    basePoint = ECDH.Point(curve, F(920), F(303))

    aliceSecretKey = ECDH.generateSecretKey(8)
    bobSecretKey = ECDH.generateSecretKey(8)

    print('Secret keys are %d, %d' % (aliceSecretKey, bobSecretKey))

    alicePublicKey = ECDH.sendDH(aliceSecretKey, basePoint, lambda x:x)
    bobPublicKey = ECDH.sendDH(bobSecretKey, basePoint, lambda x:x)

    sharedSecret1 = ECDH.receiveDH(bobSecretKey, lambda: alicePublicKey)
    sharedSecret2 = ECDH.receiveDH(aliceSecretKey, lambda: bobPublicKey)
    print('Shared secret is %s == %s' % (sharedSecret1, sharedSecret2))
    print('extracing x-coordinate to get an integer shared secret: %d' % (sharedSecret1.x.n))
    
    
    
    

    key = sharedSecret1.x.n
    bits = 256
    
    print("Key: {0:0{1}x}\n".format(key, bits//4))
    
    #Encryption
    cipher = ARIA.ARIA_encryption(plain, key, bits)
    
    print("ARIA:\n")
    print("Cipher text: {0:032x}".format(cipher))
    
    #Digital Signature: El Gamal
    print("\nDigital Signature: El Gamal:\n\nChecking signature..\n")
    #SIGN:
    # p = large prime number
    # a = generator
    # x = secret key
    # y = a^x (mod p)
    p,a,x,y = GAMAL.egKey(bits)
    s1, s2 = GAMAL.egGen(p, a, x, cipher)

    
    #VERIFY
    verify_signature = GAMAL.egVer(p, a, y, s1, s2, cipher)

    
    if not verify_signature:
        print("Bad signature")
        return
    else:
        print("Signature is valid!\n")
    
    
    #Decryption
    decrypted = ARIA.ARIA_decryption(cipher, key, bits)
    decrypted_str = hex(decrypted)[2:]  # Convert decrypted to hexadecimal string
    original = bytes.fromhex(decrypted_str).decode('utf-8')

    # Print the results



    print("Decrypted text: ",original)
    #print("Decrypted text: {0:032x}".format(decrypted))
    #print("original text: ",original)
    
    



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()


