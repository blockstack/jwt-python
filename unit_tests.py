import json
import traceback
import unittest
from test import test_support
from pybitcoin import BitcoinPrivateKey, BitcoinPublicKey
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from jwtpy import TokenSigner, TokenVerifier, decode_token


class MainTests(unittest.TestCase):
    def setUp(self):
        self.private_key_hex = 'a5c61c6ca7b3e7e55edee68566aeab22e4da26baa285c7bd10e8d2218aa3b22901'
        self.public_key_hex = '027d28f9951ce46538951e3697c62588a87f1f1f295de4a14fdd4c780fc52cfe69'
        self.private_key = BitcoinPrivateKey(self.private_key_hex, compressed=True)
        self.public_key = BitcoinPublicKey(self.public_key_hex)
        self.sample_payload = {"issuedAt": "1440713414.19"}

    def tearDown(self):
        pass

    def test_signing_decoding_and_verifying(self):
        token_signer = TokenSigner(crypto_backend=openssl_backend)
        token = token_signer.sign(self.sample_payload, self.private_key.to_pem())
        #print token
        self.assertTrue(isinstance(token, (unicode, str)))

        decoded_token = TokenVerifier.decode(token)
        self.assertTrue(isinstance(decoded_token, dict))

        decoded_token_2 = decode_token(token)
        #print json.dumps(decoded_token_2, indent=2)
        self.assertTrue(isinstance(decoded_token_2, dict))

        token_verifier = TokenVerifier()
        token_is_valid = token_verifier.verify(token, self.public_key.to_pem())
        #print token_is_valid
        self.assertTrue(token_is_valid)


def test_main():
    test_support.run_unittest(
        MainTests
    )

if __name__ == '__main__':
    test_main()
