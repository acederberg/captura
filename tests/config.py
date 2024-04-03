# =========================================================================== #
from typing import Annotated, Dict

from pydantic import BaseModel, Field, SecretStr
from yaml_settings_pydantic import YamlFileConfigDict, YamlSettingsConfigDict

# --------------------------------------------------------------------------- #
from app import util
from app.config import Config
from client import Config as ClientConfig
from client.config import ProfileConfig


class PytestSubConfig(BaseModel):
    """Configuration specific to pytest.

    :attr recreate_tables: Recreate tables or not in the ``engine`` fixture. If
        the tables do not exist, they will be created.
    """

    emit_sql: bool = False
    recreate_tables: bool = True


class PytestConfig(Config):
    """Configuration with additional pytest section.

    This should not be used in app.

    :attr tests: Test specific configuration.
    """

    model_config = YamlSettingsConfigDict(
        yaml_files=util.PATH_CONFIG_TEST_APP,
        env_prefix=util.ENV_PREFIX,
        env_nested_delimiter="__",
    )

    tests: PytestSubConfig


class PyTestClientProfileConfig(ProfileConfig):
    token: Annotated[SecretStr | None, Field()]  # type: ignore


class PytestClientConfig(ClientConfig):
    model_config = YamlSettingsConfigDict(
        yaml_files={
            util.PATH_CONFIG_TEST_CLIENT: YamlFileConfigDict(
                required=False,
                subpath=None,
            )
        }
    )

    profiles: Annotated[Dict[str, PyTestClientProfileConfig], Field()] = None  # type: ignore
