# =========================================================================== #
import base64
import json
import re
from os import path
from typing import Annotated, Any, Dict, List, Self, Tuple, overload

import httpx
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

# --------------------------------------------------------------------------- #
from app import util
from app.config import Config
from app.models import User

# NOTE: Do not touch this! This pattern will have to run against many requests.
# TODO: Appearently fastapi has this pattern somewhere. Replace this with that.
logger = util.get_logger(__name__)
PATTERN_TOKEN: re.Pattern = re.compile(
    "^(?P<token>(?P<header>[\\w_-]+).(?P<payload>[\\w_-]+).(?P<signature>[\\w_-]+))$",
    flags=re.I,
)
PATTERN_BEARER: re.Pattern = re.compile(
    "^Bearer (?P<token>(?P<header>[\\w_-]+).(?P<payload>[\\w_-]+).(?P<signature>[\\w_-]+))$",
    flags=re.I,
)
PYTEST_KID = "000-000-000"
PATH_PYTEST_PUBLIC_KEY: str = util.Path.docker("pytest-public.pem")
PATH_PYTEST_PRIVATE_KEY: str = util.Path.docker("pytest-private.pem")


# TODO: Add https://github.com/cak/secure. See https://github.com/auth0-developer-hub/api_fastapi_python_hello-world/tree/main for an example.
# https://github.com/auth0-developer-hub/api_fastapi_python_hello-world/blob/main/application/main.py
class Auth:
    """Authentication in general. Use :meth:`forAuth0` to create an instance
    that uses auth0 or use :meth:`forPyTest` to get a key pair for making
    tokens (which should only be necessary for integration tests).

    :attr private_key: The private_key, if it is provided.
    :attr public_keys: A set of public keys, probably from a JWKS.
    """

    config: Config
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
        # `issuer` and `audience` will not notice changes in config. Should not
        #  matter as config should be static.
        self.config = config
        self.issuer = self.config.auth0.issuer
        self.audience = self.config.auth0.api.audience
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

    def decode(self, raw: str, *, header: bool = True) -> Dict[str, Any]:
        """Get the key id from the JWT header and verify signature, audience,
        and issuer.

        :param raw: The raw ``authorization`` header content. This shold
            include ``Bearer``.
        :returns: The decoded JWT payload.
        """

        p = PATTERN_BEARER if header else PATTERN_TOKEN

        if (matched := p.match(raw)) is None:
            raise ValueError("Malformed JWT.")

        data_header_raw = matched.group("header") + "=="
        data_header_decoded = base64.b64decode(data_header_raw)
        data_header = json.loads(data_header_decoded)

        if (kid := data_header.get("kid")) is None:  # type: ignore
            raise ValueError("JWT header missing `kid`.")

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


# NOTE: Do not exit (via `HTTPException`) anywhere in this module besides in
#       in `try` prefixed methods.
def try_decode(
    auth: Auth,
    authorization: str,
    *,
    header: bool = True,
) -> Tuple[Dict[str, str] | None, HTTPException | None]:
    try:
        return auth.decode(authorization, header=header), None
    except jwt.DecodeError:
        _msg = "Failed to decode bearer token."
    except jwt.InvalidAudienceError:
        _msg = "Invalid bearer token audience."
    except jwt.InvalidIssuerError:
        _msg = "Invalid bearer token issuer."
    except jwt.InvalidTokenError:
        _msg = "Invalid bearer token."
    except ValueError as err:
        _msg = err.args[0]
        print(err)
    return None, HTTPException(401, detail="Invalid Token: " + _msg)


class Token(BaseModel):
    """Only used in `POST /auth/tokens` until later."""

    uuid: Annotated[str, Field()]
    admin: Annotated[bool, Field(default=False)]
    permissions: Annotated[List[str], Field(default=list())]

    def validate(self, session: Session) -> User:
        q_user = select(User).where(User.uuid == self.uuid)
        user = session.execute(q_user).scalar()
        if user is None:
            raise HTTPException(
                401,
                detail=dict(
                    msg="User with token uuid does not exist.",
                    uuid=self.uuid,
                ),
            )

        if user.admin != self.admin:
            raise HTTPException(
                401,
                detail=dict(
                    msg="Admin status inconsistent with database.",
                    uuid=self.uuid,
                    admin_token=self.admin,
                    admin_user=user.admin,
                ),
            )

        return user

    def encode(self, auth: Auth) -> str:
        return auth.encode(self.model_dump())

    def try_encode(self, auth: Auth) -> str:
        if auth.config.auth0.use:
            raise HTTPException(
                409,
                detail="Token minting is not available in auth0 mode.",
            )
        return auth.encode(self.model_dump())

    @classmethod
    def decode(cls, auth: Auth, data: str, *, header: bool = True) -> Self:
        return cls.model_validate(auth.decode(data, header=header))

    @classmethod
    def try_decode(cls, auth: Auth, data: str, *, header: bool = True) -> Self:
        decoded, err = try_decode(auth, data, header=header)
        if err is not None:
            raise err
        return cls.model_validate(decoded)
