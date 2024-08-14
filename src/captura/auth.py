# =========================================================================== #
import base64
import enum
import json
import re
from hashlib import sha256
from os import path
from typing import Annotated, Any, Dict, Iterable, Self, Set, Tuple

import httpx
import jwt
from cryptography.hazmat.backends import default_backend

# from cryptography.hazmat.backends.openssl import _RSAPrivateKey, _RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session
from typing_extensions import Doc

# --------------------------------------------------------------------------- #
from captura import util
from captura.config import Config
from captura.models import User

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

PrivateKey = Annotated[
    None | Any,
    Doc("RIP to type annotations here since the removal of `_RSAPublicKey`."),
]
PublicKey = Annotated[
    Dict[str, Any],
    Doc("RIP to type annotations here since the removal of `_RSAPublicKey`."),
]


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
    audience: str | Tuple[str, ...]
    private_key: PrivateKey
    public_keys: PublicKey

    def __init__(
        self,
        config: Config,
        public_keys: PublicKey,
        private_key: PrivateKey = None,
    ):
        # `issuer` and `audience` will not notice changes in config. Should not
        #  matter as config should be static.
        self.config = config
        self.issuer = self.config.auth0.issuer_url
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
            with (
                open(PATH_PYTEST_PUBLIC_KEY, "wb") as public_io,
                open(PATH_PYTEST_PRIVATE_KEY, "wb") as private_io,
            ):
                public_io.write(public_pem)
                private_io.write(private_pem)

        logger.debug("Loading pytest keypair.")
        with (
            open(PATH_PYTEST_PUBLIC_KEY, "rb") as public_io,
            open(PATH_PYTEST_PRIVATE_KEY, "rb") as private_io,
        ):
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

        # NOTE: Hitting this line during tests with a remote host can be the
        #       result of the configuration of the remote host and not
        #       necessarily the tests.
        if (pk := self.public_keys.get(kid)) is None:
            detail = f"Malformed Token: JWT header contains unknown key id {kid}."
            raise HTTPException(401, detail=detail)

        return jwt.decode(
            matched.group("token"),
            pk,
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
        if "iss" not in payload:
            payload["iss"] = self.issuer
        if "aud" not in payload:
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
    except jwt.InvalidTokenError as err:
        _msg = f"Invalid bearer token: {str(err)}"
    except ValueError as err:
        _msg = err.args[0]

    return None, HTTPException(401, detail="Invalid Token: " + _msg)


TokenPermissions = {
    "tier:free",
    "tier:paid",
    "tier:admin",
    "read:events",
    "read:reports",
}


class TokenPermissionTier(enum.Enum):
    """For now, only `admin` has an effect."""

    disabled = -10
    free = 0
    paid = 10
    admin = 50


class TokenPermissionRead(str, enum.Enum):
    """For reading special objects."""

    events = "events"
    reports = "reports"  # NOTE: Includes ``reports_grants``.


class TokenPermissionKind(enum.Enum):
    read = TokenPermissionRead
    tier = TokenPermissionTier


TokenPermissionPattern = re.compile("^(tier|read):([a-zA-Z]+)$")


def permission_parse(permissions: Iterable[str]) -> Dict[str, Any]:
    """Parse permissions array."""

    matched = {
        pp: mm
        for pp in permissions
        if (mm := TokenPermissionPattern.match(pp)) is not None
    }

    if len(bad := list(pp for pp in permissions if pp not in matched)):
        msg = "Raw JWT contains malformed permissions: `{}`."
        raise ValueError(msg.format(bad))

    parsed: Dict[str, Any] = dict()
    for mm in matched.values():
        key, value = mm.group(1), mm.group(2)
        parsed_value = parsed.get(key)
        match key:
            case "read":
                value_read = TokenPermissionRead(value)
                if parsed_value is None:
                    parsed["read"] = {value_read}
                else:
                    parsed["read"].add(value_read)
            case "tier":
                if parsed_value is not None:
                    msg = "`tier` can only be specified once."
                    raise ValueError(msg.format())
                parsed["tier"] = TokenPermissionTier[value]
            case _:
                raise ValueError()

    return parsed


class Token(BaseModel):
    # NOTE: uuid should not be in the token for the sake of maintainability.
    #       According to the standard [1], it should such that the ``sub``
    #       field of the jwt should be unique within the scope of the provider.
    #       The ``sub`` field is optional so it will necessary to first check
    #       that it exists.
    #
    # [1] https://www.rfc-editor.org/rfc/rfc7519#section-4.1

    subject: Annotated[str, Field(alias="sub")]
    tier: Annotated[
        TokenPermissionTier,
        Field(default=TokenPermissionTier.free),
    ]
    read: Annotated[
        Set[TokenPermissionRead],
        Field(default_factory=lambda: set()),
    ]

    @property
    def subject_256(self) -> str:
        return sha256(self.subject.encode()).hexdigest()

    @model_validator(mode="before")
    @classmethod
    def unfuck_permissions(cls, data: Any):
        if (pp := data.get("permissions")) is None:
            return data

        if "tier" in data or "read" in data:
            raise ValueError("`tier` and `read` should not be in raw data.")

        data.update(permission_parse(pp))
        return data

    def encode(self, auth: Auth) -> str:
        payload = self.model_dump(exclude={"subject", "tier", "read"})

        permissions = [f"read:{item.name}" for item in self.read]
        permissions.append(f"tier:{self.tier.name}")
        payload.update(permissions=permissions, sub=self.subject)

        return auth.encode(payload)

    # NOTE: This function is stupid. Why did I add it?
    def try_encode(self, auth: Auth) -> str:
        if auth.config.auth0.use:
            raise HTTPException(
                409,
                detail="Token minting is not available in auth0 mode.",
            )
        return self.encode(auth)

    @classmethod
    def decode(cls, auth: Auth, data: str, *, header: bool = True) -> Self:
        decoded = auth.decode(data, header=header)
        return cls.model_validate(decoded)

    # NOTE: This function is also stupid.
    @classmethod
    def try_decode(cls, auth: Auth, data: str, *, header: bool = True) -> Self:
        decoded, err = try_decode(auth, data, header=header)
        if err is not None:
            raise err

        return cls.model_validate(decoded)

    def validate_db(self, session: Session) -> User:
        q_user = select(User).where(User.subject == self.subject_256)
        user = session.execute(q_user).scalar()

        if user is None:
            raise HTTPException(
                401,
                detail=dict(
                    msg="User does not exist.",
                    subject=self.subject_256,
                ),
            )

        if user.admin and not self.tier == TokenPermissionTier.admin:
            raise HTTPException(
                401,
                detail=dict(
                    msg="Admin status inconsistent with database.",
                    subject=self.subject,
                    admin_user=user.admin,
                ),
            )

        return user
