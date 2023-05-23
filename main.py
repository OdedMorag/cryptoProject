# -*- coding: utf-8 -*-
"""
Created on Sat May  6 12:11:58 2023

@author: Nadav
"""

import ARIA_FUNC as ARIA

def main():
    my_string = 'monkey'
    plain = int(my_string.encode('utf-8').hex(), 16)

    key = 0x0123456789abcdef0123456789abcdef
    bits = 256

    cipher = ARIA.ARIA_encryption(plain, key, bits)
    decrypted = ARIA.ARIA_decryption(cipher, key, bits)
    decrypted_str = hex(decrypted)[2:]  # Convert decrypted to hexadecimal string
    original = bytes.fromhex(decrypted_str).decode('utf-8')

    # Print the results
    print("Plain text: ",my_string)
    print("Key: {0:0{1}x}".format(key, bits//4))
    print("Cipher text: {0:032x}".format(cipher))
    print("Decrypted text: {0:032x}".format(decrypted))
    print("original text: ",original)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()


