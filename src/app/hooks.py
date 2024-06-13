# =========================================================================== #
import importlib.util
import sys
from os import path
from types import ModuleType
from typing import Type

# --------------------------------------------------------------------------- #
from app import util
from app.views import AppView

logger = util.get_logger(__name__)


PATH_BASE: str = path.realpath(path.join(path.dirname(__file__), "..", ".."))
PATH_CAPTURA_HOOKS: str = path.join(PATH_BASE, "plugins/hooks.py")


def get_hooks() -> None | ModuleType:
    if not path.isfile(PATH_CAPTURA_HOOKS):
        logger.info(f"No hooks found at `{PATH_CAPTURA_HOOKS}`.")
        return

    hooks_spec = importlib.util.spec_from_file_location("hooks", PATH_CAPTURA_HOOKS)
    if hooks_spec is None:
        logger.info(f"No hooks found at `{PATH_CAPTURA_HOOKS}`.")
        return

    logger.info("Found hooks.")
    hooks = importlib.util.module_from_spec(hooks_spec)
    sys.modules["hooks"] = hooks
    hooks_spec.loader.exec_module(hooks)

    return hooks


def do_hooks(app_view: Type[AppView]):
    if (module := get_hooks()) is None:
        return None

    if (captura_plugins_app := getattr(module, "captura_plugins_app")) is None:
        return None

    captura_plugins_app(app_view)
