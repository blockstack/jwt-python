#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    An interface for encoding and decoding JSON Web Tokens (JWTs)
    ~~~~~
    :copyright: (c) 2015 by Halfmoon Labs, Inc.
    :license: MIT, see LICENSE for more details.
"""

import traceback

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key, load_pem_private_key,
    load_der_public_key, load_pem_public_key
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey
)
from keylib import ECPrivateKey, ECPublicKey
from utilitybelt import is_hex


class InvalidKeyError(ValueError):
    def __init__(self, message, errors):
        super(InvalidKeyError, self).__init__(message)
        self.errors = errors


class InvalidPrivateKeyError(InvalidKeyError):
    def __init__(self):
        message = "Signing key must be a valid private key in PEM, DER, or raw hex format."
        super(InvalidKeyError, self).__init__(message)


class InvalidPublicKeyError(InvalidKeyError):
    def __init__(self):
        message = "Verifying key must be a valid private key in PEM, DER, or raw hex format."
        super(InvalidKeyError, self).__init__(message)


def load_signing_key(signing_key, crypto_backend=default_backend()):
    """ Optional: crypto backend object from the "cryptography" python library
    """
    if isinstance(signing_key, EllipticCurvePrivateKey):
        return signing_key

    elif isinstance(signing_key, (str, unicode)):
        invalid_strings = [b'-----BEGIN PUBLIC KEY-----']
        invalid_string_matches = [
            string_value in signing_key
            for string_value in invalid_strings
        ]
        if any(invalid_string_matches):
            raise ValueError(
                'Signing key must be a private key, not a public key.')

        if is_hex(signing_key):
            try:
                private_key_pem = ECPrivateKey(signing_key).to_pem()
            except:
                pass
            else:
                try:
                    return load_pem_private_key(
                        private_key_pem, password=None, backend=crypto_backend)
                except:
                    raise InvalidPrivateKeyError()

            try:
                return load_der_private_key(
                    signing_key, password=None, backend=crypto_backend)
            except Exception as e:
                traceback.print_exc()
                raise InvalidPrivateKeyError()
        else:
            try:
                return load_pem_private_key(
                    signing_key, password=None, backend=crypto_backend)
            except:
                raise InvalidPrivateKeyError()
    else:
        raise ValueError('Signing key must be in string or unicode format.')


def load_verifying_key(verifying_key, crypto_backend=default_backend()):
    """ Optional: crypto backend object from the "cryptography" python library
    """
    if isinstance(verifying_key, EllipticCurvePublicKey):
        return verifying_key

    elif isinstance(verifying_key, (str, unicode)):
        if is_hex(verifying_key):
            try:
                public_key_pem = ECPublicKey(verifying_key).to_pem()
            except:
                pass
            else:
                try:
                    return load_pem_public_key(
                        public_key_pem, backend=crypto_backend)
                except Exception as e:
                    traceback.print_exc()
                    raise InvalidPublicKeyError()

            try:
                return load_der_public_key(
                    verifying_key, backend=crypto_backend)
            except:
                raise InvalidPublicKeyError()
        else:
            try:
                return load_pem_public_key(
                    verifying_key, backend=crypto_backend)
            except Exception as e:
                raise InvalidPublicKeyError()
    else:
        raise ValueError('Verifying key must be in string or unicode format.')
