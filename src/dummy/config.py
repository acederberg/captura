# =========================================================================== #
from typing import Annotated

from pydantic import BaseModel, Field
from yaml_settings_pydantic import BaseYamlSettings, YamlSettingsConfigDict

# --------------------------------------------------------------------------- #
from app import util
from app.config import BaseHashable
from app.config import Config as ConfigCaptura


# NOTE: Inherits from :class:`BaseHashable` because this will be used to
#       overwrite ``Depends(config)``.
class DummyConfig(BaseHashable):

    # model_config = YamlSettingsConfigDict(yaml_files=util.Path.config("dummy.yaml"))

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


class ConfigSimulatus(ConfigCaptura):
    dummy: DummyConfig
