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
from typing import Annotated

from pydantic import BaseModel, Field, SecretStr, computed_field
from sqlalchemy.engine import URL, Engine, create_engine
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from yaml_settings_pydantic import BaseYamlSettings, YamlSettingsConfigDict

# --------------------------------------------------------------------------- #
from app import util


class BaseHashable(BaseModel):
    """Hashable model.

    This enables caching of the configuration dependency.
    """

    def __hash__(self):
        return hash((type(self),) + tuple(self.__dict__.values()))


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
    username: Annotated[str, Field("documents")]
    password: Annotated[SecretStr, Field("abcd1234")]
    database: Annotated[str, Field("documents")]


class MySqlConfig(BaseHashable):
    host: MySqlHostConfig


class Auth0ApiConfig(BaseHashable):
    audience: str


class Auth0AppConfig(BaseHashable):
    client_id: str
    client_secret: SecretStr


class Auth0Config(BaseHashable):
    """

    :attr issuer: FDQN for the auth0 tenant which will issue the tokens. This
        should not contain the scheme (e.g. ``https://``) or any terminating
        ``/``.
    :attr use: Use ``auth0`` authentication when ``True``. Otherwise use a
        keypair generated by :meth:`Auth.forPyTest`. As the name indicates,
        this behaviour is desirable for tests, as using :meth:``Auth.encode``
        will enable integration testing concerning api security.
    """

    issuer: str
    use: bool = True
    api: Auth0ApiConfig
    app: Auth0AppConfig


class Environment(enum.Enum):
    production = "production"
    development = "development"


class AppConfigDev(BaseHashable):
    """Setting exclusively for development."""

    httpexc_tb: Annotated[bool, Field(default=False)]


class AppConfig(BaseHashable):
    port: Annotated[int, Field(default=8080)]
    host: Annotated[str, Field(default="0.0.0.0")]
    environment: Annotated[Environment, Field(default=Environment.production)]
    dev: Annotated[
        AppConfigDev, Field(default_factory=lambda: AppConfigDev.model_validate({}))
    ]
    logging_configuration_path: Annotated[str, Field(default=util.PATH_LOG_CONFIG)]

    @computed_field
    @property
    def is_dev(self) -> bool:
        return self.environment == Environment.development


class Config(BaseHashable, BaseYamlSettings):
    model_config = YamlSettingsConfigDict(
        yaml_files=util.PATH_CONFIG_APP,
        yaml_reload=False,
        env_prefix=util.ENV_PREFIX,
        env_nested_delimiter="__",
    )
    mysql: MySqlConfig
    auth0: Auth0Config
    app: AppConfig

    def engine(self, **kwargs) -> Engine:
        url = URL.create(
            **self.mysql.host.model_dump(
                exclude={"drivername", "drivername_async", "password"}
            ),
            password=self.mysql.host.password.get_secret_value(),
            drivername=self.mysql.host.drivername,
        )
        return create_engine(url, **kwargs)

    def async_engine(self, **kwargs) -> AsyncEngine:
        url = URL.create(
            **self.mysql.host.model_dump(
                exclude={"drivername", "drivername_async"},
            ),
            drivername=self.mysql.host.drivername_async,
        )
        return create_async_engine(url, **kwargs)
