from typing import Annotated, Dict

from app import util
from pydantic import BaseModel, Field, computed_field, model_validator
from yaml_settings_pydantic import BaseYamlSettings, YamlSettingsConfigDict

from client import flags


class ProfileConfig(BaseModel):
    # name: Annotated[str, Field()]
    uuid_user: Annotated[str, Field()]
    token: Annotated[str, Field()]


class HostConfig(BaseModel):
    host: Annotated[str, Field(default="http://localhost:8080")]
    remote: Annotated[bool, Field(default=False)]


class UseConfig(BaseModel):
    host: Annotated[str, Field(default="default")]
    profile: Annotated[str, Field(default="default")]


class Config(BaseYamlSettings):
    model_config = YamlSettingsConfigDict(yaml_files=util.PATH_CONFIG_CLIENT)

    # when host is None, use `app` instance.
    profiles: Annotated[Dict[str, ProfileConfig], Field()]
    hosts: Annotated[Dict[str, HostConfig], Field()]
    use: Annotated[UseConfig, Field()]

    @computed_field
    @property
    def host(self) -> HostConfig | None:
        return self.hosts.get(self.use.host)

    @computed_field
    @property
    def profile(self) -> ProfileConfig | None:
        return self.profiles.get(self.use.profile)

    @computed_field
    @property
    def token(self) -> str | None:
        if (pp := self.profile) is None:
            return None
            # raise ValueError("No profile to get token from.")

        return pp.token

