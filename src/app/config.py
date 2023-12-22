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

    def is_local() -> bool:
        return config.m
"""
from functools import cache
from typing import Annotated

from fastapi import Depends
from pydantic import BaseModel, Field, computed_field
from sqlalchemy.engine import URL, Engine, create_engine
from yaml_settings_pydantic import BaseYamlSettings, YamlFileConfigDict

from app.util import Path


class MySqlHostConfig(BaseModel):
    """Configuration for specifying they mysql connection.

    This should include SSL once it is necessary. All field names should be
    keyword arguments to ``sqlalchemy.engine.URL.create``.

    :attr driver: The driver to use.
    :attr host: The database hostname or IP address.
    :attr port: The port on which the database exists.
    :attr username: The login username for which connections will be
        established.
    :attr password: Password corresponding to :attr:`username`.
    """

    driver: Annotated[str, Field("mysql+mysql-connector")]
    host: Annotated[str, Field("localhost")]
    port: Annotated[int, Field(3306)]
    username: Annotated[str, Field("documents")]
    password: str


class MySqlConfig(BaseModel):
    host: MySqlHostConfig


class Config(BaseYamlSettings):
    model_config = YamlFileConfigDict(yaml_files=Path.base("config.yaml"))

    mysql: MySqlConfig

    def engine(self) -> Engine:
        url = URL.create(**self.mysql.host.model_dump())
        return create_engine(url)
