# =========================================================================== #
import json
from typing import Annotated, Dict

import typer
from pydantic import BaseModel, Field, SecretStr
from rich.console import Console
from yaml_settings_pydantic import YamlFileConfigDict, YamlSettingsConfigDict

# --------------------------------------------------------------------------- #
from app import util
from app.config import BaseHashable, Config
from app.schemas import mwargs
from client import Config as ClientConfig
from client import flags
from client.config import ProfileConfig
from client.handlers import ConsoleHandler
from client.requests.base import BaseTyperizable, typerize
from dummy import ConfigSimulatus


class PytestSubConfig(BaseHashable):
    """Configuration specific to pytest.

    :attr recreate_tables: Recreate tables or not in the ``engine`` fixture. If
        the tables do not exist, they will be created.
    """

    recreate_tables: Annotated[bool, Field(default=True)]
    generate_reports: Annotated[bool, Field(default=False)]


class PytestConfig(ConfigSimulatus):
    """Configuration with additional pytest section.

    This should not be used in app.

    :attr tests: Test specific configuration.
    """

    ...
    model_config = YamlSettingsConfigDict(
        yaml_files=util.PATH_CONFIG_TEST_APP,
        yaml_reload=False,
        env_prefix=util.ENV_PREFIX,
        env_nested_delimiter="__",
        extra="allow",
    )
    tests: PytestSubConfig


class PytestClientConfig(ClientConfig):
    model_config = YamlSettingsConfigDict(
        yaml_files={
            util.PATH_CONFIG_TEST_CLIENT: YamlFileConfigDict(
                required=False,
                subpath=None,
            )
        }
    )


class CommandConfig(BaseTyperizable):

    typer_commands = {
        "client": "print_config_client",
        "app": "print_config_app",
    }
    typer_decorate = False
    typer_check_verbage = False

    @classmethod
    def callback(
        cls, context: typer.Context, output: flags.FlagOutput = flags.Output.yaml
    ):
        console_handler = mwargs(ConsoleHandler, output=output)
        if output == flags.Output.table:
            console_handler.console.print("[red]Cannot output table.")
            raise typer.Exit()

        ConsoleHandler.console = Console()
        context.obj = console_handler

    @classmethod
    def print_config_client(cls, context: typer.Context):
        ch: ConsoleHandler = context.obj
        ch.handle(
            data=mwargs(PytestClientConfig).model_dump(
                mode="json", exclude={"hosts", "profiles", "use"}
            )
        )

    @classmethod
    def print_config_app(cls, context: typer.Context):
        ch: ConsoleHandler = context.obj
        ch.handle(data=(mwargs(PytestConfig).model_dump(mode="json")))


if __name__ == "__main__":

    tt = typerize(
        CommandConfig,
        typerize_fn=None,
        callback=CommandConfig.callback,
    )
    tt()
