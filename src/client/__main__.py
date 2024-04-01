# =========================================================================== #
from typing import Annotated, List, Optional

# --------------------------------------------------------------------------- #
from client import ConfigCommands
from client.requests import Requests


def main():
    # --------------------------------------------------------------------------- #
    from client.requests.base import typerize

    client = typerize(Requests)
    client.add_typer(typerize(ConfigCommands), name="config")
    client()
