#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Various utils taken from José Padilla's PyJWT
    ~~~~~
    :copyright: (c) 2015 by José Padilla
    :license: MIT, see LICENSE for more details.
"""

import json
import base64
import binascii
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_rfc6979_signature, encode_rfc6979_signature
)


def hex_to_int(s):
    try:
        return int(s, 16)
    except:
        raise ValueError("Value must be in hex format")


def is_hex(s):
    # make sure that s is a string
    if not isinstance(s, str):
        return False
    # if there's a leading hex string indicator, strip it
    if s[0:2] == '0x':
        s = s[2:]
    # try to cast the string as an int
    try:
        i = hex_to_int(s)
    except ValueError:
        return False
    else:
        return True


def json_encode(input):
    return json.dumps(input, separators=(',', ':')).encode('utf-8')


def base64url_decode(input):
    rem = len(input) % 4

    if rem > 0:
        input += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(input)


def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


def number_to_bytes(num, num_bytes):
    padded_hex = '%0*x' % (2 * num_bytes, num)
    big_endian = binascii.a2b_hex(padded_hex.encode('ascii'))
    return big_endian


def bytes_to_number(string):
    return int(binascii.b2a_hex(string), 16)


def der_to_raw_signature(der_sig, curve):
    num_bits = curve.key_size
    num_bytes = (num_bits + 7) // 8

    r, s = decode_rfc6979_signature(der_sig)

    return number_to_bytes(r, num_bytes) + number_to_bytes(s, num_bytes)


def raw_to_der_signature(raw_sig, curve):
    num_bits = curve.key_size
    num_bytes = (num_bits + 7) // 8

    if len(raw_sig) != 2 * num_bytes:
        raise ValueError('Invalid signature')

    r = bytes_to_number(raw_sig[:num_bytes])
    s = bytes_to_number(raw_sig[num_bytes:])

    return encode_rfc6979_signature(r, s)


class InvalidTokenError(Exception):
    pass


class DecodeError(InvalidTokenError):
    pass
