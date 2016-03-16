# JSON Tokens

[![CircleCI](https://img.shields.io/circleci/project/blockstack/jsontokens-py/master.svg)](https://circleci.com/gh/blockstack/jsontokens-py)
[![PyPI](https://img.shields.io/pypi/v/jsontokens.svg)](https://pypi.python.org/pypi/jsontokens/)
[![PyPI](https://img.shields.io/pypi/dm/jsontokens.svg)](https://pypi.python.org/pypi/jsontokens/)
[![PyPI](https://img.shields.io/pypi/l/jsontokens.svg)](https://github.com/namesystem/jsontokens/blob/master/LICENSE)
[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

### Installation

```bash
$ pip install jsontokens
```

### Importing

```python
>>> from jsontokens import TokenSigner, TokenVerifier, decode_token
```

### Signing Tokens

```python
>>> token_signer = TokenSigner()
>>> payload = {"issuedAt": "1440713414.19"}
>>> token = token_signer.sign(payload, 'a5c61c6ca7b3e7e55edee68566aeab22e4da26baa285c7bd10e8d2218aa3b22901')
>>> print token
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3N1ZWRBdCI6IjE0NDA3MTM0MTQuMTkifQ.7UpSjte-bbk0CsBgC3AJyogLKu6SGzyigFgo2qZeUN6zKHaQsBlz_pFwHkPGLmiz4yvOd5gfWu8R2BwFX55okQ
```

### Decoding Tokens

```python
>>> decoded_token = decode_token(token)
>>> import json
>>> print json.dumps(decoded_token, indent=2)
{
  "header": {
    "alg": "ES256", 
    "typ": "JWT"
  }, 
  "payload": {
    "issuedAt": "1440713414.19"
  }, 
  "signature": "7UpSjte-bbk0CsBgC3AJyogLKu6SGzyigFgo2qZeUN6zKHaQsBlz_pFwHkPGLmiz4yvOd5gfWu8R2BwFX55okQ"
}
```

### Verifying Tokens

```python
>>> token_verifier = TokenVerifier()
>>> token_is_valid = token_verifier.verify(token, '027d28f9951ce46538951e3697c62588a87f1f1f295de4a14fdd4c780fc52cfe69')
>>> print token_is_valid
True
```
