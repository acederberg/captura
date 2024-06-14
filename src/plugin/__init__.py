import yaml

# --------------------------------------------------------------------------- #
from client.handlers import CONSOLE
from client.requests.base import BaseTyperizable
from plugin.config import PluginsConfig


class PluginCommands(BaseTyperizable):
    typer_decorate = False
    typer_commands = dict(show="show", up="up")
    typer_check_verbage = False
    typer_children = dict()

    @classmethod
    def show(cls):
        config = PluginsConfig()
        CONSOLE.print(yaml.dump(config.model_dump(mode="json")))

    @classmethod
    def up(cls):
        CONSOLE.print("[green]Ensuring plugins.")
        config = PluginsConfig()
        config.ensure()
