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
        pass

    def save_message_to_file(self,filename : str,mode="w",encoding="utf-8"):
            
        if mode not in ["w","a","wt","a+","wb"]:
            raise EDQSAError(f"Invalid mode for saving message to file: {mode}")
            
        with open(filename,mode,encoding=encoding) as f:
            f.write(self.message.decode())
    
    def save_private_key_to_file(self,filename : str,private_key : bytes,mode="w",encoding="utf-8"):
                
        if mode not in ["w","a","wt","a+","wb"]:
            raise EDQSAError(f"Invalid mode for saving private key to file: {mode}")
                
        with open(filename,mode,encoding=encoding) as f:
            f.write(private_key.hex())
    
    def save_public_key_to_file(self,filename : str,public_key : bytes,mode="w",encoding="utf-8"):
                    
        if mode not in ["w","a","wt","a+","wb"]:
            raise EDQSAError(f"Invalid mode for saving public key to file: {mode}")
                    
        with open(filename,mode,encoding=encoding) as f:
            f.write(public_key.hex())
    
    
    def save_signature_to_file(self,filename : str,mode="w",encoding="utf-8"):
                    
        if mode not in ["w","a","wt","a+","wb"]:
                raise EDQSAError(f"Invalid mode for saving signature to file: {mode}")
                    
        with open(filename,mode,encoding=encoding) as f:
            f.write(self.signature.hex())
    
    
    def load_message_from_file(self,filename : str):
    
        with open(filename,"r") as f:
            self.message = f.read().encode()
    
    def load_public_key_from_file(self,filename : str):
        
        with open(filename,"r") as f:
            self.public_key = f.read().encode()
    
    def load_private_key_from_file(self,filename : str):
            
        with open(filename,"r") as f:
            self.private_key = f.read().encode()
    
    def load_signature_from_file(self,filename : str):
            
        with open(filename,"r") as f:
            self.signature = f.read().encode() 


class Ed25519Signature(EDQSAMethods):
    def __init__(self,message : bytes,public_key=None,private_key=None):
        
        self.message = message
        self.private_key = self.generate_private_key() if private_key == None else private_key
        self.public_key = self.generate_public_key() if public_key == None else public_key
        self.signature = None
        self.is_valid = False

    def generate_private_key(self) -> bytes:
        return Ed25519PrivateKey.generate()

    def generate_public_key(self) -> bytes:
        return self.private_key.public_key()

    def make_signature(self) -> bytes:
        self.signature = self.private_key.sign(self.message)
        return self.signature

    def verify_signature(self) -> bool:

        try:
            self.is_valid = self.public_key.verify(self.signature,self.message)
            if self.is_valid == None:
                self.is_valid = True
                return self.is_valid

        except InvalidSignature:
            self.is_valid = False

    
class DilithiumSignature(EDQSAMethods):

    def __init__(self,message : bytes,public_key=None,private_key=None):

        self.message = message
        self.public_key , self.private_key = ML_DSA_65.keygen() 

        if private_key != None:
            self.private_key = private_key

        if public_key != None:
            self.public_key = public_key

        self.signature = None
        self.is_valid = None
        
        
    def make_signature(self) -> bytes:
        self.signature = ML_DSA_65.sign(self.private_key,self.message)
        return self.signature
        
    def verify_signature(self) -> bool:
        self.is_valid = ML_DSA_65.verify(self.public_key,self.message,self.signature)
        return self.is_valid

    

class EDQSA(EDQSAMethods):
    def __init__(self):

        self.signature = None
        self.info = None
        self.salt = os.urandom(32)
        self.token = None
        self.is_valid = False

    def make_token(self,ed25519_signature : bytes,dilithium_signature : bytes,info : bytes,salt=None,algorithm="sha256",length=32) -> bytes:

        self.info = info
        algorithm = algorithm.strip()
        match (algorithm):

            case "sha256":
                algorithm = SHA256()

            case "sha512":
                algorithm = SHA512()

            case "md5":
                algorithm = MD5()

            case _:
                raise InvalidTokenContentError(f"Invalid algorithm: {algorithm}.EDQSA only supports md5, sha256 and sha512 algorithms.")
        if salt == None:
            salt = self.salt
        
        self.signature = ed25519_signature + dilithium_signature
        self.token = HKDF(

            algorithm=algorithm,
            length=length,
            salt=salt,
            info=info

        ).derive(self.signature)

        return self.token


    def save_token_to_file(self,filename : str,mode="w",encoding="utf-8"):
                
        if mode not in ["w","a","wt","a+","wb"]:
            raise EDQSAError(f"Invalid mode for saving token to file: {mode}")
                
        with open(filename,mode,encoding=encoding) as f:
            f.write(self.token.hex())


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


    def load_info_from_file(self,filename : str):
    
        with open(filename,"r") as f:
            self.info = f.read().encode()
    
    def load_token_from_file(self,filename : str):
        
        with open(filename,"r") as f:
            self.token = f.read().encode()
    
    def load_salt_from_file(self,filename : str):
            
        with open(filename,"r") as f:
            self.salt = f.read().encode()
    


#Exceptions

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