# =========================================================================== #
import json
from typing import Annotated

import typer
import uvicorn
import uvicorn.config
from rich.console import Console
from sqlalchemy import Engine
from sqlalchemy.engine import Connection
from sqlalchemy.orm import sessionmaker

# --------------------------------------------------------------------------- #
from app.config import Config
from app.depends import session_maker
from app.models import Base

from . import __version__, util, views

logger = util.get_logger(__name__)


CONSOLE = Console()
FlagRun = Annotated[bool, typer.Option("--run", "--exit")]
FlagDummies = Annotated[bool, typer.Option("--dummies")]
FlagRecreateTables = Annotated[bool, typer.Option("--recreate-tables")]


CONFIG = Config()  # type: ignore


class Cli:
    config: Config
    sessionmaker: sessionmaker
    engine: Engine

    def __init__(self, config: Config | None = None):
        self.config = config if config is not None else CONFIG
        self.engine = self.config.engine()
        self.sesionmaker = session_maker(self.engine)

    def show_config(self):
        CONSOLE.print_json(
            json.dumps(
                self.config.model_dump(mode="json"),
                indent=2,
            )
        )

    def run(self):
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

        uvicorn.run(
            "app.views:AppView.view_router",
            port=self.config.app.port,
            host=self.config.app.host,
            reload=self.config.app.is_dev,
            reload_dirs=util.PATH_APP if self.config.app.is_dev else None,
        )


def main() -> None:
    cli = Cli()

    tt = typer.Typer()
    tt.command("run")(cli.run)
    tt.command("config")(cli.show_config)
    tt()


# NOTE: THIS APPEARS TO BE THE BEST SPOT FOR THIS! Please see
#
#       .. code:: txt
#
#         https://github.com/encode/uvicorn/issues/491
#
LOGGING_CONFIG = util.setup_logging(CONFIG.app.logging_configuration_path)
uvicorn.config.LOGGING_CONFIG.update(LOGGING_CONFIG)


if __name__ == "__main__":
    main()
