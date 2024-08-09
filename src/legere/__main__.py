# =========================================================================== #

# --------------------------------------------------------------------------- #
from client import ConfigCommands, DockerCommand
from client.requests import Requests


def main():
    # --------------------------------------------------------------------------- #
    from client.requests.base import typerize

    client = typerize(Requests)
    client.add_typer(typerize(ConfigCommands, exclude_callback=True), name="config")
    client.add_typer(typerize(DockerCommand, exclude_callback=True), name="docker")
    client()


if __name__ == "__main__":
    main()
