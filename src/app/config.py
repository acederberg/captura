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
import logging
from functools import cache
from os import environ
from typing import Annotated, Literal

from fastapi import Depends
from pydantic import BaseModel, Field, computed_field
from sqlalchemy.engine import URL, Engine, create_engine
from yaml_settings_pydantic import (
    BaseYamlSettings,
    YamlFileConfigDict,
    YamlSettingsConfigDict,
)

from app.util import Path

PREFIX = "DOCUMENTS_SERVER_"
PATH_CONFIG = environ.get(PREFIX + "CONFIG_PATH") or Path.base("config.yaml")


class MySqlHostConfig(BaseModel):
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

    drivername: Annotated[str, Field("mysql+pymysql")]
    host: Annotated[str, Field("db")]
    port: Annotated[int, Field(3306)]
    username: Annotated[str, Field("documents")]
    password: Annotated[str, Field("abcd1234")]
    database: Annotated[str, Field("documents")]


class MySqlConfig(BaseModel):
    host: MySqlHostConfig


class AppConfig(BaseModel):
    # log_level: Literal["DEBUG", "INFO", "WARNING", "CRITICAL"]
    port: int = 8080


class Config(BaseYamlSettings):
    model_config = YamlSettingsConfigDict(
        yaml_files=PATH_CONFIG,
        yaml_reload=False,
        env_prefix=PREFIX,
        env_nested_delimiter="__",
    )
    mysql: MySqlConfig

    def engine(self, **kwargs) -> Engine:
        url = URL.create(**self.mysql.host.model_dump())
        return create_engine(url, **kwargs)
