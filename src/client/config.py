from typing import Annotated

from app import util
from pydantic import BaseModel, Field
from yaml_settings_pydantic import BaseYamlSettings, YamlSettingsConfigDict


class DefaultsConfig(BaseModel):
    uuid_user: Annotated[str, Field(default="00000000")]


class Config(BaseYamlSettings):
    model_config = YamlSettingsConfigDict(
        yaml_files=util.Path.base("client-config.yaml")
    )

    defaults: Annotated[DefaultsConfig, Field(default_factory=DefaultsConfig)]
    host: str = "http://localhost:8080"
    token: str
