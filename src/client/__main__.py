from client.config import Config
from client.requests import Requests


def main(_config: Config | None = None):
    config = _config or Config()  # type: ignore

    requests = Requests(config=config)

    typer = requests.typer
    typer()
