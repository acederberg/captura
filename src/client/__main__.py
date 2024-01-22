import fastapi
from client.config import Config
from client.requests import Requests
from client import util


def main(_config: Config | None = None):
    app = None
    config = _config or Config()  # type: ignore
    if not config.remote:
        util.CONSOLE.print("[green]Using app instance in client.")
        from app.views import AppView

        app: fastapi.FastAPI = AppView.view_router  # type: ignore

    requests = Requests(
        config=config,
        token=config.defaults.token,
        app=app,
        mode=util.Mode.cmd,
    )
    requests.typer()
