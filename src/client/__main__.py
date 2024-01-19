from client.config import Config
from client.requests import (
    Requests,
)


def main(_config: Config | None = None):
    config = _config or Config()  # type: ignore
    requests = Requests(config)
    requests.typer()


if __name__ == "__main__":
    main()
