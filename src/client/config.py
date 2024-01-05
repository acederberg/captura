from app import util
from yaml_settings_pydantic import BaseYamlSettings, YamlSettingsConfigDict


class Config(BaseYamlSettings):
    model_config = YamlSettingsConfigDict(
        yaml_files=util.Path.base("client-config.yaml")
    )

    host: str = "http://localhost:8080"
    token: str
