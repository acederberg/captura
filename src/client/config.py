from typing import Annotated, Dict
from client import flags

from app import util
from pydantic import BaseModel, computed_field, Field, model_validator
from yaml_settings_pydantic import BaseYamlSettings, YamlSettingsConfigDict


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
    def host(self) -> HostConfig | None:
        return self.hosts.get(self.use.host)

    @computed_field
    def profile(self) -> ProfileConfig | None:
        return self.profiles.get(self.use.profile)
