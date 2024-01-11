import asyncio

import httpx
import typer

from client.config import Config
from client.requests import (
    DocumentRequests,
    GrantRequests,
    UserRequests,
    CollectionRequests,
)


def main(_config: Config | None = None):
    app = typer.Typer()
    config = _config or Config()  # type: ignore
    app.add_typer(GrantRequests(config).typer, name="grant")
    app.add_typer(UserRequests(config).typer, name="user")
    app.add_typer(DocumentRequests(config).typer, name="document")
    app.add_typer(CollectionRequests(config).typer, name="collection")

    app()


if __name__ == "__main__":
    main()
