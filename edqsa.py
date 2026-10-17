
#AUTHOR: VESEL4AK31
#GITHUB: https://github.com/Vesel4ak31/EDQSA
#VERSION: 1.1
#MIT LICENSE:

# MIT License

# Copyright (c) 2026 Vesel4ak31

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


#IMPORT
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256,SHA512,MD5
from cryptography.hazmat.primitives import serialization
import os

#Main classes

class EDQSAMethods:
    def __init__(self):

        self.message = None
        self.private_key = None
        self.public_key = None
        self.signature = None

    #Save message to file
    def save_message_to_file(self,filename : str,mode="w",encoding="utf-8"):
            
        if mode not in ["w","a","wt","a+","wb"]:
            raise EDQSAError(f"Invalid mode for saving message to file: {mode}")
            
        with open(filename,mode,encoding=encoding) as f:
            f.write(self.message.decode())

    #Save private key to file
    def save_private_key_to_file(self,filename : str,private_key : bytes,mode="w",encoding="utf-8"):
                
        if mode not in ["w","a","wt","a+","wb"]:
            raise EDQSAError(f"Invalid mode for saving private key to file: {mode}")
                
        with open(filename,mode,encoding=encoding) as f:
            f.write(private_key.hex())

    #Save public key to file
    def save_public_key_to_file(self,filename : str,public_key : bytes,mode="w",encoding="utf-8"):
                    
        if mode not in ["w","a","wt","a+","wb"]:
            raise EDQSAError(f"Invalid mode for saving public key to file: {mode}")
                    
        with open(filename,mode,encoding=encoding) as f:
            f.write(public_key.hex())
    
    #Save signature to file
    def save_signature_to_file(self,filename : str,mode="w",encoding="utf-8"):
                    
        if mode not in ["w","a","wt","a+","wb"]:
                raise EDQSAError(f"Invalid mode for saving signature to file: {mode}")
                    
        with open(filename,mode,encoding=encoding) as f:
            f.write(self.signature.hex())
    
    #Load message from file
    def load_message_from_file(self,filename : str):
    
        with open(filename,"r") as f:
            self.message = f.read().encode()

    #load public key from file
    def load_public_key_from_file(self,filename : str):
        
        with open(filename,"r") as f:
            self.public_key = f.read().encode()

    #load private key from file
    def load_private_key_from_file(self,filename : str):
            
        with open(filename,"r") as f:
            self.private_key = f.read().encode()

    #load signature from file
    def load_signature_from_file(self,filename : str):
            
        with open(filename,"r") as f:
            self.signature = f.read().encode() 

#ED25519 MAIN CLASS
class Ed25519Signature(EDQSAMethods):
    def __init__(self,message : bytes,public_key=None,private_key=None):
        
        self.message = message #Message to make signature
        self.private_key = self.generate_private_key() if private_key == None else private_key #Private key
        self.public_key = self.generate_public_key() if public_key == None else public_key #Public key
        self.signature = None #Signature
        self.is_valid = False #If ed25519 sigbature Valid/Invalid

    #Generate private key
    def generate_private_key(self) -> bytes:
        return Ed25519PrivateKey.generate()

    #Generate public key
    def generate_public_key(self) -> bytes:
        return self.private_key.public_key()

    #Make ed255519 signature
    def make_signature(self) -> bytes:
        self.signature = self.private_key.sign(self.message)
        return self.signature
    
    #Verify ed25519 signature
    def verify_signature(self) -> bool:

        try:
            self.is_valid = self.public_key.verify(self.signature,self.message)
            if self.is_valid == None:
                self.is_valid = True
                return self.is_valid

        except InvalidSignature:
            self.is_valid = False
            return self.is_valid

#MAIN DilithiumSignature CLASS
class DilithiumSignature(EDQSAMethods):

    def __init__(self,message : bytes,public_key=None,private_key=None):

        self.message = message #Message to make signature
        self.public_key , self.private_key = ML_DSA_65.keygen() #Public and private key

        if private_key != None: #If private key wasnt generated
            self.private_key = private_key

        if public_key != None: #If public key wasnt generated
            self.public_key = public_key

        self.signature = None #Dilithium signature
        self.is_valid = None #If Dilithium sigbature Valid/Invalid
        
    #Make signature
    def make_signature(self) -> bytes:
        self.signature = ML_DSA_65.sign(self.private_key,self.message)
        return self.signature

    #Verify signature 
    def verify_signature(self) -> bool:
        self.is_valid = ML_DSA_65.verify(self.public_key,self.message,self.signature)
        return self.is_valid

    
#MAIN CLASS
class EDQSA(EDQSAMethods):
    def __init__(self):

        self.signature = None #Combined signature
        self.info = None #Info for HKDF
        self.salt = os.urandom(32) #SALT (DEFAULT IS OS.URANDOM(32) (RANDOM 32 BYTES) )
        self.token = None #FINAL TOKEN
        self.is_valid = False #IF TOKEN VALID / INVALID

    #MAKE TOKEN
    def make_token(self,ed25519_signature : bytes,dilithium_signature : bytes,info : bytes,salt=None,algorithm="sha256",length=32) -> bytes:

        self.info = info
        algorithm = algorithm.strip() #SELEST ALGOTITHM
        match (algorithm):

            #CHOOSE HASH ALGORITHM

            case "sha256": #
                algorithm = SHA256()

            case "sha512":
                algorithm = SHA512()

            case "md5":
                algorithm = MD5()

            case _:

                #RAISE EXCEPTION IF HASH ALGORITHM DOES NOT SUPPORTED

                raise InvalidTokenContentError(f"Invalid algorithm: {algorithm}.EDQSA only supports md5, sha256 and sha512 algorithms.")
            
        if salt == None:
            salt = self.salt

        #MAKE SIGNATURE COMBINED
        self.signature = ed25519_signature + dilithium_signature


        #!!!!!!!!!! MAIN TOKEN GENERATION !!!!!!!!!
        self.token = HKDF(

            algorithm=algorithm, #Algorithm
            length=length, #Lenght (Default is 32)
            salt=salt, #SALT
            info=info #INFO

        ).derive(self.signature) #DERIVE COMBINED SIGNATURE

        return self.token 

    #Save token to file
    def save_token_to_file(self,filename : str,mode="w",encoding="utf-8"):
                
        if mode not in ["w","a","wt","a+","wb"]:
            raise EDQSAError(f"Invalid mode for saving token to file: {mode}")
                
        with open(filename,mode,encoding=encoding) as f:
            f.write(self.token.hex())

    #Verify tolem bases on some other token
    def verify_token(self,token : bytes,info : bytes,salt : bytes,algorithm : str,length : int,signature=None,ed25519_signature=None,dilithium_signature=None) -> bool:

        algorithm = algorithm.strip()
        match (algorithm):

            case "sha256":
                algorithm = SHA256()
            case "sha512":
                algorithm = SHA512()

        if ed25519_signature == None or dilithium_signature == None:
            raise EDQSAError("None of the signatures were submitted.")

        self.signature = ed25519_signature + dilithium_signature if signature == None else signature

        if HKDF(algorithm=algorithm,length=length,salt=salt,info=info).derive(self.signature) == token:
            self.is_valid = True
            return self.is_valid

        self.is_valid = False
        return self.is_valid

    #Load info from file
    def load_info_from_file(self,filename : str):
    
        with open(filename,"r") as f:
            self.info = f.read().encode()

    #Load token from file
    def load_token_from_file(self,filename : str):
        
        with open(filename,"r") as f:
            self.token = f.read().encode()

    #Load salt from file
    def load_salt_from_file(self,filename : str):
            
        with open(filename,"r") as f:
            self.salt = f.read().encode()
    


#Exceptions

#MAIN EXCEPTION CLASS
class EDQSAError(Exception):
    pass

class InvalidTokenContentError(EDQSAError): #If anyone of content in token is invalid
    pass

class InvalidEd25519SignatureError(EDQSAError): #If Ed25519 signature is invalid
    pass

class InvalidDilithiumSignatureError(EDQSAError): #If Dilithium signature is invalid
    pass



if __name__ ==  "__main__":
    pass
