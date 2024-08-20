# =========================================================================== #
from typing import Annotated, Self

import yaml
from pydantic import Field

# --------------------------------------------------------------------------- #
from captura.config import BaseHashable
from captura.config import Config as ConfigCaptura
from captura.schemas import mwargs


class DummyItemConfig(BaseHashable):
    minimum: Annotated[int, Field()]
    maximum: Annotated[int, Field()]


class DummyGrantConfig(BaseHashable):
    maximum_self: Annotated[int, Field(default=144)]
    minimum_self: Annotated[
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

    minimum_other: Annotated[int, Field(default=64)]
    maximum_other: Annotated[int, Field(default=81)]


class DummyUserConfig(BaseHashable):
    # minimum_id: Annotated[int, Field(default=50)]
    minimum: Annotated[
        int,
        Field(
            default=125,
            description=(
                "Minimum number of users that ``DummyHandler`` will maintain "
                "in the database."
            ),
        ),
    ]
    maximum_uses: Annotated[
        int | None,
        Field(
            default=100,
            description=(
                "Number of times that a dummy may be used before it is "
                "disposed. Note that ``tainted`` dummies will still be "
                "disposed of. Generally this number should be high if tests"
                "are to complete quickly. When ``None``, dummies have no use "
                "limit."
            ),
        ),
    ]


# NOTE: Inherits from :class:`BaseHashable` because this will be used to
#       overwrite ``Depends(config)``.
class DummyConfig(BaseHashable):

    # model_config = YamlSettingsConfigDict(yaml_files=util.Path.config("dummy.yaml"))
    users: Annotated[
        DummyUserConfig,
        Field(default_factory=lambda: mwargs(DummyUserConfig)),
    ]
    documents: Annotated[
        DummyItemConfig,
        Field(
            default_factory=lambda: mwargs(
                DummyItemConfig,
                maximum=36,
                minimum=25,
            )
        ),
    ]
    collections: Annotated[
        DummyItemConfig,
        Field(
            default_factory=lambda: mwargs(
                DummyItemConfig,
                maximum=9,
                minimum=16,
            )
        ),
    ]
    grants: Annotated[
        DummyGrantConfig,
        Field(default_factory=lambda: mwargs(DummyGrantConfig)),
    ]

    @classmethod
    def load(cls, manifest_path: str) -> Self:
        with open(manifest_path, "r") as file:
            raw = yaml.safe_load(file)

        return cls.model_validate(raw)


class ConfigSimulatus(ConfigCaptura):
    dummy: DummyConfig
