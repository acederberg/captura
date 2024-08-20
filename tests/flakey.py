# =========================================================================== #
import re
from datetime import datetime
from typing import Annotated, List

import pytest
from pydantic import BaseModel, Field
from pytest import StashKey
from yaml_settings_pydantic import (
    BaseYamlSettings,
    YamlFileConfigDict,
    YamlSettingsConfigDict,
)

# --------------------------------------------------------------------------- #
from captura import util
from captura.schemas import mwargs

FLAKEY_PATH = util.path.realpath(
    util.from_env(
        "FLAKEY",
        util.Path.config("flakey.yaml"),
    )
)


# NOTE: See ``pytest_exception_interact`` for details.
class Flake(BaseModel):
    id: str
    name_parent: str | None
    name: str
    err: str
    when: str
    datetime_timestamp: float
    datetime_str: str


# NOTE: Instance is loaded in hook ``pytest_configure``.
class Flakey(BaseYamlSettings):
    model_config = YamlSettingsConfigDict(
        yaml_files={FLAKEY_PATH: YamlFileConfigDict(required=False)}
    )

    def is_ignored_node(self, node: pytest.Item) -> bool:
        matches_ignored = any(exp.match(node.name) for exp in self.ignore)
        return matches_ignored

    def is_ignored_call(self, callinfo: pytest.CallInfo) -> bool:
        if callinfo.excinfo is None:
            return True

        excstr = str(callinfo.excinfo.value)
        matches_ignored = any(exp.match(excstr) for exp in self.ignore_err)
        return matches_ignored

    def register(self, node: pytest.Item, call: pytest.CallInfo) -> None | Flake:
        if self.is_ignored_call(call) or self.is_ignored_node(node):
            return None

        self.flakes.append(
            flake := mwargs(
                Flake,
                id=node.nodeid,
                name_parent=node.parent.name if node.parent else None,
                name=node.name,
                err=str(call.excinfo.value),  # type: ignore
                when=call.when,
                datetime_str=datetime.fromtimestamp(call.stop).isoformat(),
                datetime_timestamp=call.stop,
            )
        )
        return flake

    ignore: Annotated[
        List[re.Pattern],
        Field(
            default_factory=list,
            description=(
                "Configurable as an ini option. Doing so will prevent "
                "destruction when removing or updating `flakey.yaml`."
            ),
        ),
    ]
    ignore_err: Annotated[
        List[re.Pattern],
        Field(
            default_factory=list,
            description=(
                "Configurable as an ini option. Doing so will prevent "
                "destruction when removing or updating `flakey.yaml`."
            ),
        ),
    ]
    flakes: Annotated[List[Flake], Field(default_factory=list)]


FLAKEY_STASHKEY = StashKey[Flakey]()
