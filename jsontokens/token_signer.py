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


    def _make_header(self, token_type=None, signing_algorithm=None):
        """
        Make a JWT header
        """
        if not token_type:
            token_type = self.token_type

        if not signing_algorithm:
            signing_algorithm = self.signing_algorithm

        header = {'typ': token_type, 'alg': signing_algorithm}
        return header


    def _make_signature(self, header_b64, payload_b64, signing_key):
        """
        Sign a serialized header and payload.
        Return the urlsafe-base64-encoded signature.
        """
        token_segments = [header_b64, payload_b64]
        signing_input = b'.'.join(token_segments)

        signer = self._get_signer(signing_key)
        signer.update(signing_input)
        signature = signer.finalize()

        raw_signature = der_to_raw_signature(signature, signing_key.curve)
        return base64url_encode(raw_signature)


    def _sign_single(self, payload, signing_key):
        """
        Make a single-signature JWT.
        Returns the serialized token (compact form), as a string
        """
        if not isinstance(payload, Mapping):
            raise TypeError('Expecting a mapping object, as only '
                            'JSON objects can be used as payloads.')

        token_segments = []

        signing_key = load_signing_key(signing_key, self.crypto_backend)

        header = self._make_header()
        header_b64 = base64url_encode(json_encode(header))
        payload_b64 = base64url_encode(json_encode(payload))
        signature_b64 = self._make_signature(header_b64, payload_b64, signing_key)

        token_segments = [header_b64, payload_b64, signature_b64]

        # combine the header, payload, and signature into a token and return it
        token = b'.'.join(token_segments)
        return token


    def _sign_multi(self, payload, signing_keys):
        """
        Make a multi-signature JWT.
        Returns a JSON-structured JWT.

        TODO: support multiple types of signatures
        """
        if not isinstance(payload, Mapping):
            raise TypeError('Expecting a mapping object, as only '
                            'JSON objects can be used as payloads.')

        if not isinstance(signing_keys, list):
            raise TypeError("Expecting a list of keys")

        headers = []
        signatures = []
        payload_b64 = base64url_encode(json_encode(payload))

        for sk in signing_keys:
            signing_key = load_signing_key(sk, self.crypto_backend)

            header = self._make_header()
            header_b64 = base64url_encode(json_encode(header))
            signature_b64 = self._make_signature(header_b64, payload_b64, signing_key)

            headers.append(header_b64)
            signatures.append(signature_b64)

        jwt = {
            "header": headers,
            "payload": payload_b64,
            "signature": signatures
        }

        return jwt


    def sign(self, payload, signing_key_or_keys):
        """
        Create a JWT with one or more keys.
        Returns a compact-form serialized JWT if there is only one key to sign with
        Returns a JSON-structured serialized JWT if there are multiple keys to sign with
        """
        if isinstance(signing_key_or_keys, list):
            return self._sign_multi(payload, signing_key_or_keys)

        else:
            return self._sign_single(payload, signing_key_or_keys)

