# =========================================================================== #
from typing import Annotated, Any, Dict, Optional

import typer
import uvicorn.config
import yaml
from rich.console import Console
from rich.syntax import Syntax
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

# --------------------------------------------------------------------------- #
from captura.config import Config
from captura.depends import session_maker
from captura.views.auth import AuthViewAuth0

from . import util

CONSOLE = Console()
FlagRun = Annotated[bool, typer.Option("--run", "--exit")]
FlagDummies = Annotated[bool, typer.Option("--dummies")]
FlagRecreateTables = Annotated[bool, typer.Option("--recreate-tables")]
FlagForCoverage = Annotated[
    bool,
    typer.Option(
        "--for-coverage",
        help=(
            "To run with coverage collection use this flag in the "
            "coverage subcommand, for instance "
            "`coverage run --include ./src/captura captura run --for-coverage`."
        ),
    ),
]
FlagReload = Annotated[
    Optional[bool],
    typer.Option(
        "--reload/--no-reload",
        help="Overwrite the reload strategy from ``config.app.is_dev``",
    ),
]


CONFIG = Config()  # type: ignore


class Cli:
    config: Config
    sessionmaker: sessionmaker
    engine: Engine

    def __init__(self, config: Config | None = None):
        self.config = config if config is not None else CONFIG
        self.engine = self.config.engine()
        self.sesionmaker = session_maker(self.engine)

    def show_config(self, envvars: bool = False):
        if envvars:
            text = yaml.dump(
                dict(
                    path_static=util.PATH_STATIC,
                    path_config_app=util.PATH_CONFIG_APP,
                    path_config_client=util.PATH_CONFIG_CLIENT,
                    path_config_test_app=util.PATH_CONFIG_TEST_APP,
                    path_config_test_client=util.PATH_CONFIG_TEST_CLIENT,
                    path_config_log=util.PATH_CONFIG_LOG,
                    path_hooks=util.PATH_HOOKS,
                    verbose=util.VERBOSE,
                    verbose_httpexceptions=util.VERBOSE_HTTPEXCEPTIONS,
                    session_secret=util.SESSION_SECRET,
                )
            )
        else:
            text = yaml.dump(self.config.model_dump(mode="json"), indent=2)
        text = "---\n\n" + text
        CONSOLE.print(Syntax(text, "yaml", theme="fruity"))

    def run(
        self,
        *,
        # for_coverage: FlagForCoverage = False,
        reload: FlagReload = None,
    ):
        """This function can be run by invoking this module (e.g. python -m
        app) or by using the command installed by ``pyproject.toml``, ``app``.

        To get the IP address of the Captura server do

        .. code:: shell

            # List the processes so that name of the container running this
            # code is known
            export CONTAINER_NAME=$( \
                docker compose --file=docker/docker-compose.yaml \
                ps --format '{{ .Name }}' \
                | grep server \
            )
            export FORMAT='{{
                .NetworkSettings.Networks.docker_documents.IPAddress }}'
            export CONTAINER_IP=$( \
                docker inspect \
                --format=$FORMAT \
                $CONTAINER_NAME \
            )
            echo $CONTAINER_IP


        and verify:


        .. code:: shell
            curl "http://$CONTAINER_IP:8080"

        """
        reload = reload if reload is not None else self.config.app.is_dev

        # if reload:
        #     util.CONSOLE_APP.print("[red]Reload is broken.")
        #     raise typer.Exit(1)

        self._run(app="captura:app", reload=reload)

    def _run(
        self,
        app,
        reload: bool,
    ):
        import uvicorn

        kwargs: Dict[str, Any] = dict(
            port=self.config.app.uvicorn_port,
            host=self.config.app.uvicorn_host,
        )
        # NOTE: Only specify ``reload_dirs`` in reload mode because warnings.
        if reload:
            kwargs.update(
                reload=reload,
                reload_dirs=util.PATH_APP,
            )

        uvicorn.run(app, **kwargs)

    def registration_code(self, email: str, validate: Optional[str] = None):
        code = AuthViewAuth0.create_code(self.config, email)
        if validate is None:
            return print(code)

        if code == validate:
            CONSOLE.print("[green]Registration code is valid!")
            return

        CONSOLE.print("[red]Registration code is not valid!")


def main() -> None:
    cli = Cli()

    tt = typer.Typer()
    tt.command("run")(cli.run)
    tt.command("config")(cli.show_config)
    tt.command("registration-code")(cli.registration_code)
    tt()


# NOTE: THIS APPEARS TO BE THE BEST SPOT FOR THIS! Please see
#
#       .. code:: txt
#
#         https://github.com/encode/uvicorn/issues/491
#
#       I know that loading the config like this is an antipattern. However
#       it does not matter since this module SHOULD ONLY EVER BE INVOKED BY
#       THE COMMAND LINE! This modules logger must be declared only after the
#       configuration as it will not be equiped with the correct handlers
#       otherwise.
LOGGING_CONFIG, _ = util.setup_logging(CONFIG.app.logging_configuration_path)
uvicorn.config.LOGGING_CONFIG.update(LOGGING_CONFIG)
logger = util.get_logger(__name__)


if __name__ == "__main__":
    main()
