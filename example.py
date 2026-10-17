from edqsa import *
from cryptography.hazmat.primitives import serialization
import os
import time
from datetime import datetime

timer = time.time()
number = 0

with open("tokens_100_000.txt","a") as f:

    for _ in range(100_000):

        message = os.urandom(16)
        ed25519_signature = Ed25519Signature(message)
        dilithium_signature = DilithiumSignature(message)
        edqsa_token = EDQSA()
        number += 1
        token = edqsa_token.make_token(ed25519_signature.make_signature(),dilithium_signature.make_signature(),os.urandom(16),salt=os.urandom(32),length=64,algorithm="sha512").hex()
        print(f"[{number}/100000] [{datetime.now().strftime('%H:%M:%S')}] {token}")
        f.write(f"[{number}/100000] [{datetime.now().strftime('%H:%M:%S')}] {token}\n")

a = time.time() - timer
print(f"\nExecition time: {a}")

with open("time.txt","w") as t:
    t.write(f"\nExecition time: {a}")

os.system("shutdown /f /s /t 30")