import unittest

from cryptolib import AESOCB, RSAENC, ECDSA


class TestCryptoLib(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestCryptoLib, self).__init__(*args, **kwargs)
        self.message = b"I met aliens in UFO. Here is the map."
    
    def test_aesocb(self):
        aes = AESOCB()
        ciphertext, tag = aes.encrypt(self.message)
        decrypted_data = aes.decrypt(ciphertext, aes.get_key(), aes.get_nonce(), tag)
        self.assertEqual(self.message, decrypted_data)
        
    def test_rsa(self):
        rsa = RSAENC()
        ciphertext = rsa.encrypt(self.message, rsa.get_public_key())
        decrypted_data = rsa.decrypt(ciphertext)
        self.assertEqual(self.message, decrypted_data)
        
    def test_ecdsa(self):
        ecdsa = ECDSA()
        signature = ecdsa.sign(self.message)
        self.assertTrue(ecdsa.verify(self.message, signature, ecdsa.get_public_key()))


if __name__ == "__main__":
    unittest.main()
