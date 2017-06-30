import json
import traceback
import unittest
from test import test_support
from keylib import ECPrivateKey, ECPublicKey
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from jsontokens import TokenSigner, TokenVerifier, decode_token


class MainTests(unittest.TestCase):
    def setUp(self):
        self.private_key_hex = 'a5c61c6ca7b3e7e55edee68566aeab22e4da26baa285c7bd10e8d2218aa3b22901'
        self.public_key_hex = '027d28f9951ce46538951e3697c62588a87f1f1f295de4a14fdd4c780fc52cfe69'
        self.sample_payload = {"issuedAt": "1440713414.19"}

        self.multiple_private_keys = [
            '99eca4792e019686f2b115d65224c72431d1dc361a1bacbf46daf0ed194ea07c01', 
            '43baf5d14516a295f8883425bb0b35de7e08ab126965c5775cf7a5956d2eb6b801'
        ]
        self.multiple_public_keys = [ECPrivateKey(pk).public_key().to_hex() for pk in self.multiple_private_keys]
        self.multiple_invalid_public_keys_1 = [self.public_key_hex, self.multiple_public_keys[0]]
        self.multiple_invalid_public_keys_2 = [self.public_key_hex, self.multiple_public_keys[1], self.multiple_public_keys[0]]

    def tearDown(self):
        pass

    def test_signing_decoding_and_verifying(self):
        token_signer = TokenSigner(crypto_backend=openssl_backend)
        token = token_signer.sign(self.sample_payload, self.private_key_hex)
        #print token
        self.assertTrue(isinstance(token, (unicode, str)))

        decoded_token = TokenVerifier.decode(token)
        self.assertTrue(isinstance(decoded_token, dict))

        decoded_token_2 = decode_token(token)
        #print json.dumps(decoded_token_2, indent=2)
        self.assertTrue(isinstance(decoded_token_2, dict))

        token_verifier = TokenVerifier()
        token_is_valid = token_verifier.verify(token, self.public_key_hex)
        #print token_is_valid
        self.assertTrue(token_is_valid)


    def test_signing_decoding_and_verifying_multikey(self):
        token_signer = TokenSigner()
        token = token_signer.sign(self.sample_payload, self.multiple_private_keys)
        self.assertTrue(isinstance(token, dict))

        decoded_token = TokenVerifier.decode(token)
        self.assertTrue(isinstance(decoded_token, dict))
        self.assertTrue(isinstance(decoded_token['header'], list))
        self.assertTrue(isinstance(decoded_token['signature'], list))
        self.assertTrue(len(decoded_token['header']) == 2)
        self.assertTrue(len(decoded_token['signature']) == 2)

        token_verifier = TokenVerifier()
        self.assertTrue(
            token_verifier.verify(token, self.multiple_public_keys)
        )
        self.assertTrue(
            token_verifier.verify(token, self.multiple_public_keys, num_required=1)
        )
        self.assertTrue(
            token_verifier.verify(token, self.multiple_invalid_public_keys_1, num_required=1)
        )
        self.assertTrue(
            token_verifier.verify(token, self.multiple_invalid_public_keys_2)
        )
        self.assertTrue(
            token_verifier.verify(token, self.multiple_invalid_public_keys_2, num_required=1)
        )
        self.assertTrue(
            token_verifier.verify(token, self.multiple_invalid_public_keys_2, num_required=0)
        )
        self.assertFalse(
            token_verifier.verify(token, self.multiple_invalid_public_keys_1)
        )
        self.assertFalse(
            token_verifier.verify(token, self.multiple_public_keys, num_required=3)
        )


def test_main():
    test_support.run_unittest(
        MainTests
    )

if __name__ == '__main__':
    test_main()
