#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    An interface for encoding and decoding JSON Web Tokens (JWTs)
    ~~~~~
    :copyright: (c) 2015 by Halfmoon Labs, Inc.
    :license: MIT, see LICENSE for more details.
"""

import json
import base64
import binascii
import traceback
from collections import Mapping
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.exceptions import InvalidSignature

from .utils import (
    base64url_encode, base64url_decode, der_to_raw_signature,
    raw_to_der_signature, json_encode, DecodeError
)
from .key_loading import load_signing_key


class TokenSigner():
    def __init__(self, crypto_backend=default_backend()):
        self.crypto_backend = crypto_backend
        self.token_type = 'JWT'
        self.signing_algorithm = 'ES256K'
        self.signing_function = ec.ECDSA(hashes.SHA256())

    def _get_signer(self, signing_key):
        return signing_key.signer(self.signing_function)

    def sign(self, payload, signing_key):
        if not isinstance(payload, Mapping):
            raise TypeError('Expecting a mapping object, as only '
                            'JSON objects can be used as payloads.')

        token_segments = []

        signing_key = load_signing_key(signing_key, self.crypto_backend)

        # prepare header
        header = {'typ': self.token_type, 'alg': self.signing_algorithm}
        token_segments.append(base64url_encode(json_encode(header)))

        # prepare payload
        token_segments.append(base64url_encode(json_encode(payload)))

        # prepare signature
        signing_input = b'.'.join(token_segments)
        signer = self._get_signer(signing_key)
        signer.update(signing_input)
        signature = signer.finalize()
        raw_signature = der_to_raw_signature(signature, signing_key.curve)
        token_segments.append(base64url_encode(raw_signature))

        # combine the header, payload, and signature into a token and return it
        token = b'.'.join(token_segments)
        return token
