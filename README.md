# JSON Tokens

### Installation

```bash
$ pip install jsontokens
```

### Signing Tokens

```python
from jsontokens import TokenSigner
from pybitcoin import BitcoinPrivateKey

token_signer = TokenSigner()
private_key_hex = 'a5c61c6ca7b3e7e55edee68566aeab22e4da26baa285c7bd10e8d2218aa3b22901'
private_key_pem = BitcoinPrivateKey(private_key_hex, compressed=True).to_pem()
payload = {"issuedAt": "1440713414.19"}
token = token_signer.sign(payload, private_key_pem)
```

The token will look something like this:

```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3N1ZWRBdCI6IjE0NDA3MTM0MTQuMTkifQ.7UpSjte-bbk0CsBgC3AJyogLKu6SGzyigFgo2qZeUN6zKHaQsBlz_pFwHkPGLmiz4yvOd5gfWu8R2BwFX55okQ
```

### Decoding Tokens

```python
from jsontokens import decode_token

decoded_token = decode_token(token)
```

```python
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
from jsontokens import TokenVerifier
from pybitcoin import BitcoinPublicKey

token_verifier = TokenVerifier()
public_key_pem = BitcoinPublicKey('027d28f9951ce46538951e3697c62588a87f1f1f295de4a14fdd4c780fc52cfe69').to_pem()
token_is_valid = token_verifier.verify(token, public_key_pem)
```

```python
>>> print token_is_valid
True
```
