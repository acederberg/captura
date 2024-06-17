# =========================================================================== #

# --------------------------------------------------------------------------- #
from client import ConfigCommands
from client.requests import Requests


def main():
    # --------------------------------------------------------------------------- #
    from client.requests.base import typerize

    client = typerize(Requests)
    client.add_typer(typerize(ConfigCommands, exclude_callback=True), name="config")
    client()


if __name__ == "__main__":
    main()
