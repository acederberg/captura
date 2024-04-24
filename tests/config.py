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

    minimum_count_documents: Annotated[int, Field(default=25)]
    maximum_count_documents: Annotated[int, Field(default=36)]

    minimum_count_collections: Annotated[int, Field(default=9)]
    maximum_count_collections: Annotated[int, Field(default=16)]

    maximum_count_grants_self: Annotated[int, Field(default=144)]
    minimum_count_grants_self: Annotated[
        int,
        Field(
            default=81,
            gt=24,
            description=(
                "Minimum number of grants to create for a particular "
                "user. Must be greater than 24 so that all users have a "
                "chance of having documents in all possible permutations of"
                "``(pending, level, PendingFrom.granter | PendingFrom.grantee,"
                " deleted)``. When this occurs, an errors is not thrown but "
                "instead a warning is produced in logs."
            ),
        ),
    ]

    minimum_count_grants_other: Annotated[int, Field(default=64)]
    maximum_count_grants_other: Annotated[int, Field(default=81)]


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
