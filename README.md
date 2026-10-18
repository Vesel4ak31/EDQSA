# EDQSA is an algorithm for generating one-time secure tokens, written entirely in Python.

# How it works

All necessary classes are defined in the `edqsa.py` file. The algorithm itself involves creating one lightweight Ed25519 signature and one robust post-quantum Dilithium signature, which are then combined using an HMAC-based Key Derivation Function (HKDF). The operational principle is illustrated in the figure below.

<img width="1536" height="1169" alt="изображение" src="https://github.com/user-attachments/assets/13884e39-de90-454a-8557-bbc077d57199" />


# Why use this algorithm?

<img width="450" height="450" alt="изображение" src="https://github.com/user-attachments/assets/d1dbf4d2-e713-41b5-8c06-3cb4ef7b0ef8" /> <img width="450" height="450" alt="изображение" src="https://github.com/user-attachments/assets/7a1ce9be-7b10-4448-8ccd-aa35706aaae4" />

As of 2026, corporations such as IBM and Microsoft are developing quantum computers capable of easily compromising contemporary encryption algorithms, including RSA. Consequently, cryptographers worldwide have begun seeking methods to safeguard data against quantum-based threats. To understand the basics of how quantum computers function, one must look at the fundamentals of quantum mechanics and computer science. While a classical bit can hold one of two values—0 or 1—quantum computers utilize qubits. A qubit, the fundamental unit of quantum information, can exist in a state of superposition, representing both 0 and 1 simultaneously. The concept of quantum superposition is often illustrated using the famous thought experiment known as "Schrödinger's cat." For further explanation, see: https://en.wikipedia.org/wiki/Schr%C3%B6dinger%27s_cat
Returning to the topic at hand: thanks to the work of scientists globally, the advanced Dilithium digital signature algorithm has been developed. Based on the concept of quantum lattices, it is designed to be resistant to quantum computing. Meanwhile, the time-tested Ed25519 signature remains a reliable standard, still widely used today in protocols such as SSH. My algorithm generates one lightweight Ed25519 signature and one heavyweight Dilithium signature; these, along with additional data—such as a salt and an "info" parameter—are then fed into a key derivation function (HKDF). This produces a final key of arbitrary length, composed of both the lightweight and heavyweight signatures. Crucially, the algorithm is one-time use; the resulting output cannot be decrypted, meaning it functions strictly in one direction. The core purpose is to serve as definitive proof that a specific signature belongs to a specific owner—and to no one else.

<img width="1000" height="700" alt="изображение" src="https://github.com/user-attachments/assets/dddda5ee-e32c-4e11-9116-96a8f52c51bb" />

# More on Dilithium and Ed25519 Signatures

<img width="510" height="357" alt="изображение" src="https://github.com/user-attachments/assets/07280689-911d-447c-bc17-245c076d4838" /> <img width="1207" height="347" alt="изображение" src="https://github.com/user-attachments/assets/4c5ac31f-1673-4dc3-9549-4b76117c14b5" />

The whole point of cryptographic signatures is to create a "fingerprint" that can be verified using cryptographic keys. My algorithm supports this as well.
As shown in the top diagram, there are two types of signatures involved: the lightweight Ed25519 and the much more computationally intensive Dilithium. Both can be verified against their respective public and private keys to confirm that they belong to the owner. Once these signatures are combined, the result is fed into an HKDF (HMAC-based Key Derivation Function), yielding a key of any desired length.
Furthermore, my algorithm allows you to include not just a message, but also your own public and private keys. You have full control over parameters such as key length and salt, and you can choose from several hashing algorithms: MD5, SHA-256, or SHA-512—the latter being my personal recommendation. I strongly advise against using MD5, as it is outdated and insecure; however, I have included it simply for the sake of variety.
As you can see, I have added functionality to verify and compare signatures—this is illustrated in the screenshots below. I believe this makes the algorithm significantly more versatile.

<img width="881" height="458" alt="изображение" src="https://github.com/user-attachments/assets/23c2cfb8-fda8-4085-acba-143524f8e03b" /> <img width="690" height="502" alt="изображение" src="https://github.com/user-attachments/assets/02063c48-e53a-48dc-9167-51f2c8151997" />

