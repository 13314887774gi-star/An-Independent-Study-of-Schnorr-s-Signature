# -*- coding: utf-8 -*-
"""
Created on Mon Mar 16 23:23:32 2026

@author: wangyunong
"""

from cryptography.hazmat.primitives.asymmetric import dsa
from schnorr_signature import SchnorrSignature


dsa_private_key = dsa.generate_private_key(key_size=2048)


numbers = dsa_private_key.private_numbers()
p = numbers.public_numbers.parameter_numbers.p
q = numbers.public_numbers.parameter_numbers.q
g = numbers.public_numbers.parameter_numbers.g


schnorr = SchnorrSignature(p, q, g)

private_key, public_key = schnorr.generate_keys()
message = b"Hello"
signature = schnorr.sign(message, private_key)

print(schnorr.verify(message, public_key, signature))