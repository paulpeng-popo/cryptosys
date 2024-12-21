from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes


class AESOCB:
    def __init__(self, key_len=32, nonce_len=15):
        """Generate a new AES key and nonce.

        Args:
            key_len (int, optional): key length in bytes. Defaults to 32.
            nonce_len (int, optional): nonce length in bytes. Defaults to 15.
        """
        self.key = get_random_bytes(key_len)
        self.nonce = get_random_bytes(nonce_len)
        
    def encrypt(self, data):
        """Encrypt the data using AES-OCB.

        Args:
            data: Data to be encrypted.

        Returns:
            ciphertext: Encrypted data.
            tag: Authentication tag.
        """
        cipher = AES.new(self.key, AES.MODE_OCB, nonce=self.nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, tag
    
    def decrypt(self, ciphertext, key, nonce, tag):
        """Decrypt the ciphertext using AES-OCB.

        Args:
            ciphertext: Encrypted data.
            key: AES key.
            nonce: AES nonce.
            tag: Authentication tag.

        Returns:
            Decrypted data.
        """
        cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data
    
    def get_key(self):
        """Get the AES key.

        Returns:
            AES key.
        """
        return self.key
    
    def get_nonce(self):
        """Get the AES nonce.

        Returns:
            AES nonce.
        """
        return self.nonce


class RSAENC:
    def __init__(self, key_length=3072):
        """Generate a new RSA key pair.
        - public_key is used for encryption. Share it with others.
        - private_key is used for decryption. DO NOT SHARE IT.
        """
        self.key = RSA.generate(key_length)
        self.public_key = self.key.publickey()
        
    def encrypt(self, data, public_key):
        """Encrypt the data using recipient's public key.
        
        Args:
            data: Data to be encrypted.
            public_key: Recipient's public key.
            
        Returns:
            Encrypted data.
        """
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(data)
        return ciphertext
    
    def decrypt(self, ciphertext):
        """Decrypt the ciphertext using the private key.
        
        Args:
            ciphertext: Encrypted data.
            
        Returns:
            Decrypted data.
        """
        cipher = PKCS1_OAEP.new(self.key)
        data = cipher.decrypt(ciphertext)
        return data
    
    def get_public_key(self):
        return self.public_key


class ECDSA:
    def __init__(self):
        """Generate a new ECC key pair.
        - private_key is used for signing. DO NOT SHARE IT.
        - public_key is used for verification. Share it with others.
        """
        self.private_key = ECC.generate(curve="P-256")
        self.public_key = self.private_key.public_key()
        
    def sign(self, data):
        """Sign the data with the private key.

        Args:
            data: Data to be signed.

        Returns:
            Signature of the data.
        """
        h = SHA256.new(data)
        signer = DSS.new(self.private_key, "fips-186-3")
        signature = signer.sign(h)
        return signature
    
    def verify(self, data, signature, public_key):
        """Verify the signature of the data.

        Args:
            data: Data to be verified.
            signature: Signature of the data.
            public_key: Public key of the signer.

        Returns:
            True if the signature is valid, False otherwise
        """
        h = SHA256.new(data)
        verifier = DSS.new(public_key, "fips-186-3")
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False
    
    def get_public_key(self):
        return self.public_key
    