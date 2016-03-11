# JWT Python

### Installation

```bash
$ pip install jwtpy
```

### Importing

```python
from jwtpy import TokenSigner, TokenVerifier
```

### Signing Tokens

```python
token_signer = TokenSigner(crypto_backend=openssl_backend)
token = token_signer.sign(self.sample_decoded_token_payload, self.private_key.to_pem())
```

### Decoding Tokens

```python
decoded_token = TokenVerifier.decode(token)
```

### Verifying Tokens

```
token_verifier = TokenVerifier()
token_is_valid = token_verifier.verify(token, self.public_key.to_pem())
```