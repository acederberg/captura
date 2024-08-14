# =========================================================================== #
import enum
from typing import Annotated, Any, Dict, Literal, Self

import yaml
from pydantic import (
    BaseModel,
    Field,
    SecretStr,
    computed_field,
    model_validator,
)
from yaml_settings_pydantic import (
    BaseYamlSettings,
    YamlFileConfigDict,
    YamlSettingsConfigDict,
)

# --------------------------------------------------------------------------- #
from captura import util

# NOTE: Previously this was part of the console handler. However the same
#       data is necessary in a number of places and is therefore factored out.


class Output(str, enum.Enum):
    raw = "raw"
    json = "json"
    yaml = "yaml"
    table = "table"


class OutputConfig(BaseModel):

    decorate: Annotated[bool, Field(default=True)]
    output: Annotated[Output, Field(default=Output.yaml)]
    output_fallback: Annotated[
        Literal[Output.yaml, Output.json],
        Field(
            default=Output.yaml,
            description="Because some data cannot be nicely rendered as a table.",
        ),
    ]
    rich_theme: str = "fruity"

    # output_exclude: Annotated[Set[str], Field(default_factory=set)]
    # table_columns: Annotated[FlagColumns, Field(default_factory=list)]
    # table_column_configs: Annotated[
    #     Dict[str, Dict[str, Any]], Field(default_factory=dict)
    # ]


class ProfileConfig(BaseModel):
    # name: Annotated[str, Field()]
    uuid_user: Annotated[str, Field()]
    token: Annotated[SecretStr | None, Field(default=None)]


class HostConfig(BaseModel):
    host: Annotated[str, Field(default="http://localhost:8080")]
    remote: Annotated[bool, Field(default=False)]


class UseConfig(BaseModel):
    host: Annotated[str, Field(default="default")]
    profile: Annotated[str, Field(default="default")]


class Config(BaseYamlSettings):
    # NOTE
    model_config = YamlSettingsConfigDict(  # type: ignore
        yaml_files={
            util.PATH_CONFIG_CLIENT: YamlFileConfigDict(
                envvar=util.prefix_env("CONFIG_CLIENT"),
            )
        },
        extra="allow",
    )

    output: Annotated[OutputConfig, Field()]
    profiles: Annotated[Dict[str, ProfileConfig], Field()]
    hosts: Annotated[Dict[str, HostConfig], Field()]
    use: Annotated[UseConfig, Field()]

    # NOTE: See https://github.com/acederberg/pydantic-settings-yaml/issues/22.
    def dump(self, config_path: str) -> None:
        data = self.model_dump_config()
        # print()
        # print("dump", data["output"])
        # print("dump", config_path)
        # print()
        with open(config_path, "w") as file:
            yaml.dump(data, file)

    @model_validator(mode="after")
    def check_use_valid(self):
        fmt = "Invalid %s config `%s`, should be any of `%s`."
        if (uu := self.use.host) not in (vv := self.hosts):
            raise ValueError(fmt % ("host", uu, vv))

        if (uu := self.use.profile) not in (vv := self.profiles):
            raise ValueError(fmt % ("profile", uu, vv))

        return self

    # NOTE: See https://github.com/acederberg/pydantic-settings-yaml/issues/22.
    @classmethod
    def load(cls, config_path: str) -> Self:
        with open(config_path, "r") as file:
            config = cls.model_validate(yaml.safe_load(file))
        return config

    @computed_field  # type: ignore[prop-decorator]
    @property
    def host(self) -> HostConfig:
        if (hh := self.hosts.get(self.use.host)) is None:
            raise ValueError()

        return hh

    @computed_field  # type: ignore[prop-decorator]
    @property
    def profile(self) -> ProfileConfig:
        if (pp := self.profiles.get(self.use.profile)) is None:
            raise ValueError()

        return pp

    @computed_field  # type: ignore[prop-decorator]
    @property
    def token(self) -> SecretStr | None:
        if (pp := self.profile) is None:
            return None

        return pp.token

    def model_dump_minimal(self) -> Dict[str, Any]:
        "Create minimal output for display."

        data = self.model_dump(
            mode="json",
            include={"profile", "host", "output"},
        )
        return data

    def model_dump_config(self) -> Dict[str, Any]:
        "Create file output as a python dictionary."

        data = self.model_dump(
            mode="json",
            include={"profiles", "hosts", "output", "use"},
        )
        for profile_name, profile in data["profiles"].items():
            token_secret = self.profiles[profile_name].token
            token = (
                token_secret.get_secret_value() if token_secret is not None else None
            )
            profile["token"] = token

        return data
