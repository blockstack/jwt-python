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
from .key_loading import load_verifying_key


def _unpack_token_compact(token):
    """
    Unpack a compact-form serialized JWT.
    Returns (header, payload, signature, signing_input) on success
    Raises DecodeError on bad input
    """
    if isinstance(token, (str, unicode)):
        token = token.encode('utf-8')

    try:
        signing_input, crypto_segment = token.rsplit(b'.', 1)
        header_segment, payload_segment = signing_input.split(b'.', 1)
    except ValueError:
        raise DecodeError('Not enough segments')

    try:
        header_data = base64url_decode(header_segment)
    except (TypeError, binascii.Error):
        raise DecodeError('Invalid header padding')

    try:
        header = json.loads(header_data.decode('utf-8'))
    except ValueError as e:
        raise DecodeError('Invalid header string: %s' % e)

    if not isinstance(header, Mapping):
        raise DecodeError('Invalid header string: must be a json object')

    try:
        payload_data = base64url_decode(payload_segment)
    except (TypeError, binascii.Error):
        raise DecodeError('Invalid payload padding')

    try:
        payload = json.loads(payload_data.decode('utf-8'))
    except ValueError as e:
        raise DecodeError('Invalid payload string: %s' % e)

    try:
        signature = base64url_decode(crypto_segment)
    except (TypeError, binascii.Error):
        raise DecodeError('Invalid crypto padding')

    return (header, payload, signature, signing_input)


def _unpack_token_json(token):
    """
    Unpack a JSON-serialized JWT
    Returns (headers, payload, signatures) on success
    Raises DecodeError on bad input
    """
    if not isinstance(token, dict):
        raise DecodeError("Not a dict")

    if not token.has_key('payload'):
        raise DecodeError("Missing 'payload' field")

    for k in ['header', 'signature']:
        if not token.has_key(k):
            raise DecodeError("Missing '{}' field".format(k))

        if not isinstance(token[k], list):
            raise DecodeError("Field '{}' is not a string".format(k))

    headers = []
    signatures = []
    signing_inputs = []
    payload = None

    try:
        headers = [base64url_decode(str(h)) for h in token['header']]
    except (TypeError, binascii.Error):
        raise DecodeError("Invalid header padding")

    try:
        payload_data = base64url_decode(str(token['payload']))
    except (TypeError, binascii.Error):
        raise DecodeError("Invalid payload padding")

    try:
        payload = json.loads(payload_data.decode('utf-8'))
    except ValueError as e:
        raise DecodeError('Invalid payload string: {}'.format(e))

    try:
        signatures = [base64url_decode(str(s)) for s in token['signature']]
    except (TypeError, binascii.Error):
        raise DecodeError("Invalid crypto padding")

    for header_b64 in token['header']:
        signing_inputs.append( b'{}.{}'.format(header_b64, token['payload']) )

    return (headers, payload, signatures, signing_inputs)


def unpack_token(token):
    """
    Unpack a JSON-serialized JWT or a compact-serialized JWT
    Returns (header, payload, signature, signing_input) on success
    Raises DecodeError on bad input
    """
    if isinstance(token, (unicode,str)):
        return _decode_token_compact(token)

    else:
        return _decode_token_json(token)


def _decode_token_compact(token):
    """
    Decode a compact-serialized JWT
    Returns {'header': ..., 'payload': ..., 'signature': ...}
    """
    header, payload, raw_signature, signing_input = _unpack_token_compact(token)
    token = { 
        "header": header,
        "payload": payload,
        "signature": base64url_encode(raw_signature)
    }
    return token


def _decode_token_json(token):
    """
    Decode a JSON-serialized JWT
    Returns {'header': ..., 'payload': ..., 'signature': ...}
    """
    header, payload, raw_signatures, signing_inputs = _unpack_token_json(token)
    token = {
        'header': header,
        'payload': payload,
        'signature': [base64url_encode(rs) for rs in raw_signatures]
    }
    return token


def decode_token(token):
    """
    Top-level method to decode a JWT.
    Takes either a compact-encoded JWT with a single signature,
    or a multi-sig JWT in the JSON-serialized format.

    Returns the deserialized token, as a dict.
    The signatures will still be base64-encoded
    """
    if isinstance(token, (unicode,str)):
        return _decode_token_compact(token)

    else:
        return _decode_token_json(token)


class TokenVerifier():
    def __init__(self, crypto_backend=default_backend()):
        self.crypto_backend = crypto_backend
        self.token_type = 'JWT'
        self.signing_algorithm = 'ES256K'
        self.signing_function = ec.ECDSA(hashes.SHA256())

    def _get_verifier(self, verifying_key, signature):
        return verifying_key.verifier(signature, self.signing_function)

    def _verify_single(self, token, verifying_key):
        """
        Verify a compact-formatted JWT signed by a single key
        Return True if authentic
        Return False if not
        """
        # grab the token parts
        header, payload, raw_signature, signing_input = _unpack_token_compact(token)

        # load the verifying key
        verifying_key = load_verifying_key(verifying_key, self.crypto_backend)
        
        # convert the raw_signature to DER format
        der_signature = raw_to_der_signature(
            raw_signature, verifying_key.curve)
        
        # initialize the verifier
        verifier = self._get_verifier(verifying_key, der_signature)
        verifier.update(signing_input)
        
        # check to see whether the signature is valid
        try:
            verifier.verify()
        except InvalidSignature:
            # raise DecodeError('Signature verification failed')
            return False
        return True


    def _verify_multi(self, token, verifying_keys, num_required=None):
        """
        Verify a JSON-formatted JWT signed by multiple keys is authentic.
        Optionally set a threshold of required valid signatures with num_required.
        Return True if valid
        Return False if not

        TODO: support multiple types of keys
        """
        headers, payload, raw_signatures, signing_inputs = _unpack_token_json(token)
        if num_required is None:
            num_required = len(raw_signatures)

        if num_required > len(verifying_keys):
            # not possible
            return False

        if len(headers) != len(raw_signatures):
            # invalid 
            raise DecodeError('Header/signature mismatch')

        verifying_keys = [load_verifying_key(vk, self.crypto_backend) for vk in verifying_keys]

        # sanity check: only support one type of key :(
        for vk in verifying_keys:
            if vk.curve.name != verifying_keys[0].curve.name:
                raise DecodeError("TODO: only support using keys from one curve per JWT")
                
        der_signatures = [raw_to_der_signature(rs, verifying_keys[0].curve) for rs in raw_signatures]

        # verify until threshold is met
        num_verified = 0
        for (signing_input, der_sig) in zip(signing_inputs, der_signatures):
            for vk in verifying_keys:
                verifier = self._get_verifier(vk, der_sig)
                verifier.update(signing_input)
                try:
                    verifier.verify()
                    num_verified += 1
                    verifying_keys.remove(vk)
                    break
                except InvalidSignature:
                    pass

            if num_verified >= num_required:
                break

        return (num_verified >= num_required)

    
    def verify(self, token, verifying_key_or_keys, num_required=None):
        """
        Verify a compact-formated JWT or a JSON-formatted JWT signed by multiple keys.
        Return True if valid
        Return False if not valid

        TODO: support multiple types of keys
        """
        if not isinstance(verifying_key_or_keys, (list, str, unicode)):
            raise ValueError("Invalid verifying key(s): expected list or string")

        if isinstance(verifying_key_or_keys, list):
            return self._verify_multi(token, verifying_key_or_keys, num_required=num_required)

        else:
            return self._verify_single(token, str(verifying_key_or_keys))
        

    @classmethod
    def decode(cls, token):
        return decode_token(token)
