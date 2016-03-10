import json
import traceback
import unittest
from test import test_support
from pybitcoin import BitcoinPrivateKey, BitcoinPublicKey
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from jwtpy import TokenSigner, TokenVerifier


class MainTests(unittest.TestCase):
    def setUp(self):
        self.private_key_hex = 'a5c61c6ca7b3e7e55edee68566aeab22e4da26baa285c7bd10e8d2218aa3b22901'
        self.public_key_hex = '027d28f9951ce46538951e3697c62588a87f1f1f295de4a14fdd4c780fc52cfe69'
        self.private_key = BitcoinPrivateKey(self.private_key_hex, compressed=True)
        self.public_key = BitcoinPublicKey(self.public_key_hex)
        self.sample_encoded_token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3N1ZWRBdCI6IjE0NDA3MTM0MTQuMTkiLCJjaGFsbGVuZ2UiOiIxZDc4NTBkNy01YmNmLTQ3ZDAtYTgxYy1jMDA4NTc5NzY1NDQiLCJwZXJtaXNzaW9ucyI6WyJibG9ja2NoYWluaWQiXSwiaXNzdWVyIjp7InB1YmxpY0tleSI6IjAzODI3YjZhMzRjZWJlZTZkYjEwZDEzNzg3ODQ2ZGVlYWMxMDIzYWNiODNhN2I4NjZlMTkyZmEzNmI5MTkwNjNlNCIsImRvbWFpbiI6Im9uZW5hbWUuY29tIn19.96Q_O_4DX8uPy1enosEwS2sIcyVelWhxvfj2F8rOvHldhqt9YRYilauepb95DVnmpqpCXxJb7jurT8auNCbptw'
        self.sample_decoded_token_payload = {"issuedAt": "1440713414.19", "challenge": "1d7850d7-5bcf-47d0-a81c-c00857976544", "issuer": {"publicKey": "03827b6a34cebee6db10d13787846deeac1023acb83a7b866e192fa36b919063e4", "domain": "onename.com"}, "permissions": ["blockchainid"]}

    def tearDown(self):
        pass

    def test_token_signing_and_verifying(self):
        token_signer = TokenSigner(crypto_backend=openssl_backend)
        token = token_signer.sign(self.sample_decoded_token_payload, self.private_key.to_pem())
        #print token
        self.assertTrue(isinstance(token, (unicode, str)))
        decoded_token = TokenVerifier.decode(token)
        #print json.dumps(decoded_token, indent=2)
        self.assertTrue(isinstance(decoded_token, dict))
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
