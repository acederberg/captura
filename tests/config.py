# =========================================================================== #
from typing import Annotated, ClassVar

import pytest
import typer
from pydantic import Field
from rich.console import Console
from typing_extensions import Doc
from yaml_settings_pydantic import YamlFileConfigDict, YamlSettingsConfigDict

# --------------------------------------------------------------------------- #
from captura import util
from captura.config import BaseHashable, Config
from captura.schemas import mwargs
from legere import Config as ClientConfig
from legere import flags
from legere.handlers import ConsoleHandler
from legere.requests.base import BaseTyperizable, typerize
from simulatus import ConfigSimulatus


class PytestSubConfig(BaseHashable):
    """Configuration specific to pytest.

    :attr recreate_tables: Recreate tables or not in the ``engine`` fixture. If
        the tables do not exist, they will be created.
    """

    generate_reports: Annotated[
        bool,
        Field(
            default=False,
            description=(
                "When ``True``, a dummy report is generated before the "
                "execution of each module. If ``generate_dummies`` is ``True``"
                "then reports will be created after ``DummyHandler.dispose`` "
                "and ``DummyHandler.restore`` is called."
            ),
        ),
    ]
    generate_dummies: Annotated[bool, Field(default=False)]


# NOTE: Yes, I tried putting classvar inside the annotation. It didn't work.
PytestConf = Annotated[
    pytest.Config,
    Doc(
        "The actual pytest configuration. This is here to give access to "
        "any necessary information about pytest without having to update "
        "signatures."
    ),
]


class PytestConfig(ConfigSimulatus, Config):
    """Configuration with additional pytest section.

    This should not be used in app.

    :attr tests: Test specific configuration.
    """

    pytestconfig: ClassVar[PytestConf]
    model_config = YamlSettingsConfigDict(
        yaml_files={
            util.PATH_CONFIG_TEST_APP: YamlFileConfigDict(required=True),
        },
        yaml_reload=False,
        env_prefix=util.ENV_PREFIX,
        env_nested_delimiter="__",
        extra="allow",
    )

    tests: PytestSubConfig


class PytestClientConfig(ClientConfig):
    pytestconfig: ClassVar[PytestConf]
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
