# EDQSA is an algorithm for generating one-time secure tokens, written entirely in Python.

# Installation

```
git clone https://github.com/Vesel4ak31/EDQSA.git
cd EDQSA
pip install -r requirements.txt --break-system-packages
```

# How it works

All necessary classes are defined in the `edqsa.py` file. The algorithm itself involves creating one lightweight Ed25519 signature and one robust post-quantum Dilithium signature, which are then combined using an HMAC-based Key Derivation Function (HKDF). The operational principle is illustrated in the figure below.

<img width="1536" height="1169" alt="изображение" src="https://github.com/user-attachments/assets/13884e39-de90-454a-8557-bbc077d57199" />


# Why use this algorithm?

<img width="450" height="450" alt="изображение" src="https://github.com/user-attachments/assets/d1dbf4d2-e713-41b5-8c06-3cb4ef7b0ef8" /> <img width="450" height="450" alt="изображение" src="https://github.com/user-attachments/assets/7a1ce9be-7b10-4448-8ccd-aa35706aaae4" />

As of 2026, corporations such as IBM and Microsoft are developing quantum computers capable of easily compromising contemporary encryption algorithms, including RSA. Consequently, cryptographers worldwide have begun seeking methods to safeguard data against quantum-based threats. To understand the basics of how quantum computers function, one must look at the fundamentals of quantum mechanics and computer science. While a classical bit can hold one of two values—0 or 1—quantum computers utilize qubits. A qubit, the fundamental unit of quantum information, can exist in a state of superposition, representing both 0 and 1 simultaneously. The concept of quantum superposition is often illustrated using the famous thought experiment known as "Schrödinger's cat." For further explanation, see: https://en.wikipedia.org/wiki/Schr%C3%B6dinger%27s_cat
Returning to the topic at hand: thanks to the work of scientists globally, the advanced Dilithium digital signature algorithm has been developed. Based on the concept of quantum lattices, it is designed to be resistant to quantum computing. Meanwhile, the time-tested Ed25519 signature remains a reliable standard, still widely used today in protocols such as SSH. My algorithm generates one lightweight Ed25519 signature and one heavyweight Dilithium signature; these, along with additional data—such as a salt and an "info" parameter—are then fed into a key derivation function (HKDF). This produces a final key of arbitrary length, composed of both the lightweight and heavyweight signatures. Crucially, the algorithm is one-time use; the resulting output cannot be decrypted, meaning it functions strictly in one direction. The core purpose is to serve as definitive proof that a specific signature belongs to a specific owner—and to no one else.

<img width="1400" height="700" alt="изображение" src="https://github.com/user-attachments/assets/dddda5ee-e32c-4e11-9116-96a8f52c51bb" />

# More on Dilithium and Ed25519 Signatures

<img width="1207" height="347" alt="изображение" src="https://github.com/user-attachments/assets/4c5ac31f-1673-4dc3-9549-4b76117c14b5" />


The whole point of cryptographic signatures is to create a "fingerprint" that can be verified using cryptographic keys. My algorithm supports this as well.
As shown in the top diagram, there are two types of signatures involved: the lightweight Ed25519 and the much more computationally intensive Dilithium. Both can be verified against their respective public and private keys to confirm that they belong to the owner. Once these signatures are combined, the result is fed into an HKDF (HMAC-based Key Derivation Function), yielding a key of any desired length.
Furthermore, my algorithm allows you to include not just a message, but also your own public and private keys. You have full control over parameters such as key length and salt, and you can choose from several hashing algorithms: MD5, SHA-256, or SHA-512—the latter being my personal recommendation. I strongly advise against using MD5, as it is outdated and insecure; however, I have included it simply for the sake of variety.
As you can see, I have added functionality to verify and compare signatures—this is illustrated in the screenshots below. I believe this makes the algorithm significantly more versatile.

<img width="690" height="502" alt="изображение" src="https://github.com/user-attachments/assets/02063c48-e53a-48dc-9167-51f2c8151997" />


# About EDQSA

<img width="2032" height="401" alt="изображение" src="https://github.com/user-attachments/assets/e7737021-1e76-44e2-9c8d-38a930aa77bf" />

This is the core class in the code. It takes two signatures as arguments. As mentioned earlier, we combine these signatures and use HKDF to derive a key. There is also a feature for verifying signatures. You might ask: how can a signature be verified if the algorithm is described as "one-time"? The answer is simple: to perform a verification, we take the token in question and provide the signatures, salt, and "info" parameter as input data. Essentially, we regenerate a token based on this input and compare it to the original. An important note: the resulting token is in a byte format; use the `hex()` method to represent it as a hexadecimal string.


#About example.py

<img width="2003" height="234" alt="изображение" src="https://github.com/user-attachments/assets/fdad6e69-704f-4236-9684-acfbe1be9a2e" />

The `example.py` file contains an example of how to use the program. It demonstrates generating two signatures and deriving the final token. Naturally, `example.py` does not showcase the full range of functionality—it focuses specifically on the generation of one-time tokens.

# The EDQSAMethods Helper Class and Exceptions

<img width="2020" height="1237" alt="изображение" src="https://github.com/user-attachments/assets/ccc8c245-6624-48a8-82e7-0f425a06bc85" />

The first class contains general methods that are subsequently inherited by the classes for Ed25519 and Dilithium signatures. This class includes methods for loading and saving data—such as info, salt, and keys—to and from files, making it easy to store data or retrieve it for later use. There are also several exception classes; the comments indicate the specific scenarios in which these exceptions are raised. In fact, the code is heavily commented, making it easy to follow. Should you find any part of it unclear, you can always seek assistance from an AI.

<img width="1149" height="276" alt="изображение" src="https://github.com/user-attachments/assets/ec63da34-1b3a-4f4c-80e1-51f273e9837c" />

# License
To save you from having to look up the LICENSE file, I have included its contents here. The license is also stated at the very top of the `edqsa.py` file:

```

MIT License

Copyright (c) 2026 Vesel4ak31

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

# On Improving the Algorithm and the Origin of the Idea

The idea for this algorithm came to me about a year ago, while I was reading David Wong’s book *Real World Cryptography*. The author mentioned that it would be interesting to see a hybrid signature algorithm. Something clicked in my mind at that moment; I began thinking about how to create such an algorithm, but I hit a snag regarding signature verification. Later, I concluded that it would be interesting to develop an algorithm for one-time tokens. I believe that, thanks to my Asperger’s syndrome, my brain is capable of retaining a vast amount of information for long periods. In any case, if anything else occurs to me, I will certainly incorporate it into the algorithm. The autistic brain is wired in such a way that when a brilliant idea emerges, I am highly likely to implement it immediately.

# Disclaimer

While this project is certainly unconventional, I must emphasize that the algorithm is intended solely for legal use and contains nothing malicious.


