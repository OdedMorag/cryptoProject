#!/usr/bin/env python
# encoding:UTF-8
"""

Implement the following routine: 
	
	(Integer, Integer) pair(Integer)

such that pair(d) will return (p,a) containing a safe prime p with 
d bits and a generator a for Z∗p.

"""
import Crypto.Util.number as num
import random

# def pair(s):
#     safe_prime = 0
#     while(True):
#         p = num.getPrime(s)
#         for g in range(2, p):
#             elements = set()
#             for i in range(1, p):
#                 element = (g ** i) % p
#                 elements.add(element)
#                 if len(elements) == p - 1:
#                     return p,g


def pair(s):
    while(True):
        p = num.getPrime(s)
        for g in range(2, p):
            if(pow(g,p-1,p)==1):
                return p,g
        