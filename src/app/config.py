"""Module for application configuration.

The main class defined here is `Config`. This should not `import` any internal 
modules because it will result in circular imports. `Config` will be included
in controllers by dependency injection. For example, do not do

.. code:: python

    from app.config import config

    def is_local() -> bool:
        return config.mysql.host.host


Instead do

.. code:: python

    from app import depends

    def is_local(config: Annotated[Config, Depends(Config)]) -> bool:
        return config.m
"""

# =========================================================================== #
import enum
import secrets
import typing
from typing import Annotated, Any, ClassVar, Dict, Literal, Set, Tuple, Unpack

from pydantic import BaseModel, ConfigDict, Field, SecretStr, computed_field
from pydantic.fields import FieldInfo
from sqlalchemy.engine import URL, Engine, create_engine
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from starlette.config import Config as StarletteConfig
from typing_extensions import Doc
from yaml_settings_pydantic import BaseYamlSettings, YamlSettingsConfigDict

# --------------------------------------------------------------------------- #
from app import util


class BaseHashable(BaseModel):
    """Hashable model.

    This enables caching of the configuration dependency.
    """

    hashable_fields_exclude: ClassVar[Set[str]]
    model_config = ConfigDict(extra="allow")

    def __init_subclass__(cls, **kwargs: Unpack[ConfigDict]):
        """Compute fields to exclude from hashing.

        Only dictionary fields are excluded from hashing, so changes in any
        such fields will no be considered by ``fastapi.Depends``.
        """
        super().__init_subclass__(**kwargs)
        cls.model_fields
        cls.hashable_fields_exclude = {
            key
            for key, value in cls.model_fields.items()
            if cls.inspect_model_field(value)
        }

    @classmethod
    def inspect_model_field(cls, value: FieldInfo) -> bool:
        # NOTE: Do not hash dicts.
        return typing.get_origin(value.annotation) != dict

    def __hash__(self):
        return hash(
            (type(self),)
            + tuple(
                value
                for key, value in self.__dict__.items()
                if self.inspect_model_field(self.model_fields[key])
            )
        )


class MySqlHostConfig(BaseHashable):
    """Configuration for specifying they mysql connection.

    This should include SSL once it is necessary. All field names should be
    keyword arguments to ``sqlalchemy.engine.URL.create``.

    :attr driver: The driver to use.
    :attr host: The database hostname or IP address. This defaults to the
        hostname assigned to the ``db`` container by the docker compose
        project.
    :attr port: The port on which the database exists. Defaults to ``3306``,
        the default MySQL port.
    :attr username: The login username for which connections will be
        established. This defaults to the username defined in the docker
        compose project.
    :attr password: Password corresponding to :attr:`username`.
    :attr database: The hosts database to use.
    """

    drivername_async: Annotated[str, Field("mysql+asyncmy")]
    drivername: Annotated[str, Field("mysql+pymysql")]
    host: Annotated[str, Field("db")]
    port: Annotated[int, Field(3306)]
    username: Annotated[str, Field("captura")]
    password: Annotated[SecretStr, Field("changeme")]
    database: Annotated[str, Field("captura")]


class MySqlConfig(BaseHashable):
    host: MySqlHostConfig
    engine_kwargs: Annotated[
        Dict[str, Any],
        Field(default_factory=lambda: dict()),
    ]


class Auth0ApiConfig(BaseHashable):
    audience: str | Tuple[str, ...]


class Auth0AppConfig(BaseHashable):
    client_id: str
    client_secret: SecretStr
    secret_key: Annotated[
        SecretStr, Field(default_factory=lambda: SecretStr(secrets.token_urlsafe(32)))
    ]


class Auth0Config(BaseHashable):
    """

    :attr use: Use ``auth0`` authentication when ``True``. Otherwise use a
        keypair generated by :meth:`Auth.forPyTest`. As the name indicates,
        this behaviour is desirable for tests, as using :meth:``Auth.encode``
        will enable integration testing concerning api security.
    """

    registration_code_salt: Annotated[
        bytes,
        Field(
            description=(
                "Salt for the registration code. This should be some sort of "
                "random string. See ``UserView.post_user`` and https://auth0.com/docs/customize/actions/write-your-first-action#add-a-secret"
                "about adding a secret to auth0 actions."
            )
        ),
    ]
    # registration_delay: Annotated[int, Field(description="Maximum registration code delay.")]
    issuer: Annotated[
        str,
        Field(
            description=(
                "FDQN for the auth0 tenant which will issue the tokens. This"
                " should not contain the scheme (e.g. ``https://``) or any "
                "terminating ``/``."
            )
        ),
    ]
    use: bool = True
    api: Auth0ApiConfig
    app: Auth0AppConfig

    @property
    def issuer_url(self) -> str:
        # NOTE: Standard is to not include the terminating backslash, but this
        #       is how auth0 made it so whatever.
        return f"https://{self.issuer}/"


class Environment(enum.Enum):
    production = "production"
    development = "development"


class AppConfigDev(BaseHashable):
    """Setting exclusively for development."""

    httpexc_tb: Annotated[bool, Field(default=False)]


class AppConfig(BaseHashable):
    uvicorn_port: Annotated[int, Field(default=8080)]
    uvicorn_host: Annotated[str, Field(default="0.0.0.0")]

    host_dns_name: Annotated[
        str,
        Field(default="captura.local"),
        Doc("Must not include scheme. See `host_scheme`."),
    ]
    host_scheme: Annotated[
        Literal["http://", "https://"],
        Field(default="https://"),
    ]
    host_port: Annotated[int | None, Field(default=8080)]

    environment: Annotated[
        Environment,
        Field(default=Environment.production),
    ]
    dev: Annotated[
        AppConfigDev,
        Field(default_factory=lambda: AppConfigDev.model_validate({})),
    ]
    logging_configuration_path: Annotated[
        str,
        Field(default=util.PATH_CONFIG_LOG),
    ]

    @computed_field
    @property
    def is_dev(self) -> bool:
        return self.environment == Environment.development

    @computed_field
    @property
    def host_url(self) -> str:
        host = f"{self.host_scheme}{self.host_dns_name}"
        if self.host_port is not None:
            host = f"{host}:{self.host_port}"
        return host


class Config(BaseHashable, BaseYamlSettings):
    model_config = YamlSettingsConfigDict(
        yaml_files=util.PATH_CONFIG_APP,
        yaml_reload=False,
        env_prefix=util.ENV_PREFIX,
        env_nested_delimiter="__",
        extra="allow",
    )
    mysql: MySqlConfig
    auth0: Auth0Config
    app: AppConfig

    def engine(self, **engine_kwargs_extra) -> Engine:
        url = URL.create(
            **self.mysql.host.model_dump(
                exclude={"drivername", "drivername_async", "password"}
            ),
            password=self.mysql.host.password.get_secret_value(),
            drivername=self.mysql.host.drivername,
        )
        engine_kwargs = self.mysql.engine_kwargs.copy()
        engine_kwargs.update(engine_kwargs_extra)
        return create_engine(url, **engine_kwargs)

    def async_engine(self, **kwargs) -> AsyncEngine:
        url = URL.create(
            **self.mysql.host.model_dump(
                exclude={"drivername", "drivername_async"},
            ),
            drivername=self.mysql.host.drivername_async,
        )
        return create_async_engine(url, **kwargs)
