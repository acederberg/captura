import base64
import json
import secrets
from typing import Any, Dict

import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import Config


class Auth:
    """Authentication in general. Use :meth:`forAuth0` to create an instance
    that uses auth0 or use :meth:`forPyTest` to get a key pair for making
    tokens (which should only be necessary for integration tests).

    :attr private_key: The private_key, if it is provided.
    :attr public_keys: A set of public keys, probably from a JWKS.
    """

    private_key: None | _RSAPrivateKey
    public_keys: Dict[str, _RSAPublicKey]

    def __init__(
        self,
        public_keys: Dict[str, _RSAPublicKey],
        private_key: None | _RSAPrivateKey = None,
    ):
        self.private_key = private_key
        self.public_keys = public_keys

    @classmethod
    def forAuth0(cls, config):
        issuer = config.auth0.issuer
        result = requests.get(f"https://{issuer}/.well-known/jwks.json")
        if result.status_code != 200:
            raise ValueError(f"Failed to fetch JWKS from issuer `{issuer}`.")

        jwks = result.json()

        # NOTE: I went through so much garbage documentation to find this in
        #       stack exchange post, lol.
        # https://stackoverflow.com/questions/68891213/how-to-decode-jwt-token-with-jwk-in-python
        public_keys = {}
        for jwk in jwks["keys"]:
            kid = jwk["kid"]
            _ = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
            public_keys[kid] = _

        return cls(public_keys)

    @classmethod
    def forPyTest(cls):
        # https://gist.github.com/gabrielfalcao/de82a468e62e73805c59af620904c124
        kid = secrets.token_hex(4)
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        public_key = private_key.public_key()

        return cls({kid: public_key}, private_key)  # type: ignore

    def decode(self, config, raw: str) -> Dict[str, Any]:
        split = raw.split(".")
        if not len(split) == 3:
            raise ValueError("Malformed JWT: Not enough segments.")
        print(split[0])
        payload = base64.b64decode(str(split[0]) + "==")
        payload = json.loads(payload)
        kid = payload["kid"]  # type: ignore
        return jwt.decode(
            raw,
            self.public_keys[kid],
            algorithms="RS256",
            audience=config.auth0.api.audience,
            issuer=config.auth0.issuer,
        )

    def encode(self, config, payload) -> str:
        if self.private_key is None:
            raise ValueError("Cannot encode without a private key.")
        kid = list(self.public_keys.keys())[0]
        payload["iss"] = config.auth0.issuer
        payload["aud"] = config.auth0.api.audience
        return jwt.encode(
            payload, self.private_key, algorithm="RS256", headers={"kid": kid}
        )


# config = Config()
# Auth.fromConfig(config)

# test = Auth.forPyTest()
# terd = test.encode(dict(foo="bar"))
# print(terd)
# decoded = test.decode(terd)
# print(decoded)
