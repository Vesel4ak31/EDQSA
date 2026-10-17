from edqsa import *
import os

ed25519_signature = Ed25519Signature(b"5bdaa95f27731c24e67c1835c645df90fc2c95534c61308a16ce48ff9a243e9d") #Make ed25519 signature with message
dilithium_signature = DilithiumSignature(b"0c578501b2d67341c59a4800d2d0895b5fa583f8b133b2001b932e2197ac268b") #Make dilithium signature with message


edqsa = EDQSA()
token = edqsa.make_token(ed25519_signature.make_signature(),dilithium_signature.make_signature(),b"d32d864d6f7606a9f477ef90af6ebe7294569d5a8a2ebd8f89ec4da01cd50c44",salt = os.urandom(32),length=64).hex() #Make token

print(token)


