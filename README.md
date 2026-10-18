# EDQSA is an algorithm for generating one-time secure tokens, written entirely in Python.

# How it works

All necessary classes are defined in the `edqsa.py` file. The algorithm itself involves creating one lightweight Ed25519 signature and one robust post-quantum Dilithium signature, which are then combined using an HMAC-based Key Derivation Function (HKDF). The operational principle is illustrated in the figure below.
<img width="1536" height="1169" alt="AA" src="https://github.com/user-attachments/assets/c309a7e6-7364-4669-b170-c16f011d607d" />

# Why use this algorithm?

<img width="450" height="450" alt="изображение" src="https://github.com/user-attachments/assets/d1dbf4d2-e713-41b5-8c06-3cb4ef7b0ef8" /> <img width="450" height="450" alt="изображение" src="https://github.com/user-attachments/assets/7a1ce9be-7b10-4448-8ccd-aa35706aaae4" />

As of 2026, corporations such as IBM and Microsoft are developing quantum computers capable of easily compromising contemporary encryption algorithms, including RSA. Consequently, cryptographers worldwide have begun seeking methods to safeguard data against quantum-based threats. To understand the basics of how quantum computers function, one must look at the fundamentals of quantum mechanics and computer science. While a classical bit can hold one of two values—0 or 1—quantum computers utilize qubits. A qubit, the fundamental unit of quantum information, can exist in a state of superposition, representing both 0 and 1 simultaneously. The concept of quantum superposition is often illustrated using the famous thought experiment known as "Schrödinger's cat." For further explanation, see: https://en.wikipedia.org/wiki/Schr%C3%B6dinger%27s_cat
Returning to the topic at hand: thanks to the work of scientists globally, the advanced Dilithium digital signature algorithm has been developed. Based on the concept of quantum lattices, it is designed to be resistant to quantum computing. Meanwhile, the time-tested Ed25519 signature remains a reliable standard, still widely used today in protocols such as SSH. My algorithm generates one lightweight Ed25519 signature and one heavyweight Dilithium signature; these, along with additional data—such as a salt and an "info" parameter—are then fed into a key derivation function (HKDF). This produces a final key of arbitrary length, composed of both the lightweight and heavyweight signatures. Crucially, the algorithm is one-time use; the resulting output cannot be decrypted, meaning it functions strictly in one direction. The core purpose is to serve as definitive proof that a specific signature belongs to a specific owner—and to no one else.

<img width="1000" height="700" alt="изображение" src="https://github.com/user-attachments/assets/dddda5ee-e32c-4e11-9116-96a8f52c51bb" />

