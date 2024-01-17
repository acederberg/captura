import base64
import json
import re
import secrets
from os import path
from typing import Any, Dict

import jwt
import httpx
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import util
from app.config import Config

# Do not touch this! This pattern will have to run against many requests.
logger = util.get_logger(__name__)
PATTERN_BEARER: re.Pattern = re.compile(
    "^Bearer (?P<token>(?P<header>[\\w_-]+).(?P<payload>[\\w_-]+).(?P<signature>[\\w_-]+))$",
    flags=re.I,
)
PYTEST_KID = "000-000-000"
PATH_PYTEST_PUBLIC_KEY: str = util.Path.docker("pytest-public.pem")
PATH_PYTEST_PRIVATE_KEY: str = util.Path.docker("pytest-private.pem")


class Auth:
    """Authentication in general. Use :meth:`forAuth0` to create an instance
    that uses auth0 or use :meth:`forPyTest` to get a key pair for making
    tokens (which should only be necessary for integration tests).

    :attr private_key: The private_key, if it is provided.
    :attr public_keys: A set of public keys, probably from a JWKS.
    """

    issuer: str
    audience: str
    private_key: None | _RSAPrivateKey
    public_keys: Dict[str, _RSAPublicKey]

    def __init__(
        self,
        config: Config,
        public_keys: Dict[str, _RSAPublicKey],
        private_key: None | _RSAPrivateKey = None,
    ):
        self.issuer = config.auth0.issuer
        self.audience = config.auth0.api.audience
        self.private_key = private_key
        self.public_keys = public_keys

    @classmethod
    def forAuth0(cls, config):
        logger.debug("Getting Auth0 JWKS.")
        issuer = config.auth0.issuer
        result = httpx.get(f"https://{issuer}/.well-known/jwks.json")
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

        return cls(config, public_keys)

    @classmethod
    def forPyTest(cls, config):
        # https://gist.github.com/gabrielfalcao/de82a468e62e73805c59af620904c124
        if not path.exists(PATH_PYTEST_PRIVATE_KEY) or not path.exists(
            PATH_PYTEST_PUBLIC_KEY
        ):
            logger.debug("Generating test authorization.")
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096, backend=default_backend()
            )
            public_key = private_key.public_key()
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            with open(PATH_PYTEST_PUBLIC_KEY, "wb") as public_io, open(
                PATH_PYTEST_PRIVATE_KEY, "wb"
            ) as private_io:
                public_io.write(public_pem)
                private_io.write(private_pem)

        logger.debug("Loading pytest keypair.")
        with open(PATH_PYTEST_PUBLIC_KEY, "rb") as public_io, open(
            PATH_PYTEST_PRIVATE_KEY, "rb"
        ) as private_io:
            public_key = serialization.load_pem_public_key(
                public_io.read(), backend=default_backend()
            )
            private_key = serialization.load_pem_private_key(
                private_io.read(), password=None, backend=default_backend()
            )

        logger.debug("Done loading!")
        return cls(config, {PYTEST_KID: public_key}, private_key)  # type: ignore

    def decode(self, raw: str) -> Dict[str, Any]:
        """Get the key id from the JWT header and verify signature, audience,
        and issuer.

        :param raw: The raw ``authorization`` header content. This shold
            include ``Bearer``.
        :returns: The decoded JWT payload.
        """
        matched = PATTERN_BEARER.match(raw)
        if matched is None:
            raise ValueError("Malformed JWT.")
        header = base64.b64decode(matched.group("header") + "==")
        header = json.loads(header)
        kid = header["kid"]  # type: ignore
        return jwt.decode(
            matched.group("token"),
            self.public_keys[kid],
            algorithms="RS256",  # type: ignore
            audience=self.audience,
            issuer=self.issuer,
        )

    def encode(self, payload) -> str:
        """When a private key is provided, use this to mint new tokens.

        This can be helpful in testing with pytest or messing around with cURL,

        :param payload: The JWT payload.
        """
        if self.private_key is None:
            raise ValueError("Cannot encode without a private key.")
        kid = list(self.public_keys.keys())[0]
        payload["iss"] = self.issuer
        payload["aud"] = self.audience
        return jwt.encode(
            payload, self.private_key, algorithm="RS256", headers={"kid": kid}
        )
