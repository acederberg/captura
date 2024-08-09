# =========================================================================== #
from typing import Type

# --------------------------------------------------------------------------- #
from app import hooks, util
from client.requests import Requests

logger = util.get_logger(__name__)


def do_hooks(client_command: Type[Requests]):
    if (module := hooks.get_hooks()) is None:
        return None

    if (captura_plugins_client := getattr(module, "captura_plugins_client")) is None:
        return None

    captura_plugins_client(client_command)
