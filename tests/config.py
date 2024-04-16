# =========================================================================== #
from typing import Annotated, Dict

from pydantic import BaseModel, Field, SecretStr
from yaml_settings_pydantic import YamlFileConfigDict, YamlSettingsConfigDict

# --------------------------------------------------------------------------- #
from app import util
from app.config import Config
from client import Config as ClientConfig
from client.config import ProfileConfig


class PytestDummyConfig(BaseModel):
    minimum_count: Annotated[int, Field(default=125)]
    minimum_user_id: Annotated[int, Field(default=50)]
    maximum_use_count: Annotated[int, Field(default=3)]
    autodispose: Annotated[bool, Field(default=False)]


class PytestSubConfig(BaseModel):
    """Configuration specific to pytest.

    :attr recreate_tables: Recreate tables or not in the ``engine`` fixture. If
        the tables do not exist, they will be created.
    """

    dummies: Annotated[PytestDummyConfig, Field(default=dict(), validate_default=True)]
    recreate_tables: Annotated[bool, Field(default=True)]


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
