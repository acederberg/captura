from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from sqlalchemy import Engine
from sqlalchemy.engine import Connection
from sqlalchemy.orm import sessionmaker

from app.config import Config
from app.depends import session_maker
from app.models import Base

from . import __version__, util, views

logger = util.get_logger(__name__)


CONSOLE = Console()
FlagRun = Annotated[bool, typer.Option("--run", "--exit")]
FlagDummies = Annotated[bool, typer.Option("--dummies")]
FlagRecreateTables = Annotated[bool, typer.Option("--recreate-tables")]


class Cli:

    config: Config
    sessionmaker: sessionmaker
    engine: Engine

    def __init__(self, config: Config | None = None):
        self.config = config if config is not None else Config()
        self.engine = self.config.engine()
        self.sesionmaker = session_maker(self.engine)

    def __call__(
        self,
        recreate_tables: FlagRecreateTables = False,
        run: FlagRun = True,
        dummies: FlagDummies = False,
    ) -> None:
        if recreate_tables:
            CONSOLE.print("[green]Recreating tables.")
            metadata = Base.metadata
            metadata.drop_all(self.engine)
            metadata.create_all(self.engine)
        if dummies:
            CONSOLE.print("[green]Loading tables.")
            self.try_load_tables()
        if run:
            CONSOLE.print("[green]Serving app with uvicorn.")
            uvicorn.run(
                "app.views:AppView.view_router",
                port=8080,
                host="0.0.0.0",
                reload=True,
                reload_dirs=util.PATH_APP,
            )

        raise typer.Exit(0)

    def try_load_tables(self):
        try:
            from captura_tests.test_models import ModelTestMeta
        except ImportError as err:
            CONSOLE.print("[red]Missing tests. Cannot load.")
            CONSOLE.print(err)
            raise typer.Exit(1)
        ModelTestMeta.load(self.sessionmaker)

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
            port=8080,
            host="0.0.0.0",
            reload=True,
            reload_dirs=util.PATH_APP,
        )


def main() -> None:
    cli = Cli()

    tt = typer.Typer()
    tt.command("run")(cli)
    tt()


# THIS APPEARS TO BE THE BEST SPOT FOR THIS!
util.setup_logging()


if __name__ == "__main__":
    main()
