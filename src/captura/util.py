# =========================================================================== #
import enum
import logging
import logging.config
import logging.handlers
import os
import pathlib
import secrets
from os import environ, path
from typing import Any, Type

import yaml
from rich.console import Console
from rich.syntax import Syntax
from sqlalchemy.orm import Session

LOG_LEVEL = environ.get("CAPTURA_LOGS_LEVEL", "INFO")
logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger(__name__)

# =========================================================================== #
# PATH STUFF


class Path:
    @classmethod
    def ensure(cls, dirpath: str) -> None:
        if path.isfile(dirpath):
            raise ValueError(f"`{dirpath}` should not be a file.")

        if path.isdir(dirpath) or path.exists(dirpath):
            return

        os.mkdir(dirpath)

    @classmethod
    def base(cls, v: str) -> str:
        return path.join(PATH_BASE, v)

    @classmethod
    def app(cls, v: str) -> str:
        return path.join(PATH_APP, v)

    @classmethod
    def tests(cls, v: str) -> str:
        return path.join(PATH_TESTS, v)

    @classmethod
    def test_assets(cls, v: str) -> str:
        return path.join(PATH_TESTS_ASSETS, v)

    @classmethod
    def simulatus_assets(cls, v: str) -> str:
        o = path.join(PATH_SIMULATUS_ASSETS, v)
        return o

    @classmethod
    def docker(cls, v: str) -> str:
        if PATH_DOCKER is None:
            raise ValueError("Docker assets are not available in packaged project.")

        return path.join(PATH_DOCKER, v)

    @classmethod
    def config(cls, v: str) -> str:
        return path.join(PATH_CONFIG, v)

    @classmethod
    def plugins(cls, v: str) -> str:
        return path.join(PATH_PLUGINS, v)


_PATH_PARENT = path.realpath(path.dirname(path.dirname(__file__)))
logger.warning(_PATH_PARENT)

PATH_DOCKER: str | None = None
IS_PACKAGED = _PATH_PARENT.endswith("site-packages")

# NOTE: Paths for dev mode and package mode are different.
if not IS_PACKAGED:
    logger.debug("Using development paths.")

    PATH_BASE: str = path.realpath(path.join(path.dirname(__file__), "..", ".."))
    PATH_APP: str = path.join(PATH_BASE, "src/captura")
    PATH_SIMULATUS = path.join(PATH_BASE, "src/simulatus")
    PATH_CLIENT: str = path.join(PATH_BASE, "src/legere")

    PATH_CONFIG: str = path.join(PATH_BASE, "configs")
    PATH_DOCKER = path.join(PATH_BASE, "docker")
    PATH_PLUGINS: str = path.join(PATH_BASE, "plugins")
else:
    logger.debug("Using packaged paths.")

    PATH_BASE: str = _PATH_PARENT
    PATH_APP: str = path.join(PATH_BASE, "captura")
    PATH_SIMULATUS = path.join(PATH_BASE, "simulatus")
    PATH_CLIENT: str = path.join(PATH_BASE, "legere")

    try:
        _PATH_HOME = os.environ["HOME"]
    except KeyError as err:
        raise ValueError("Could not resolve `Home`.") from err

    PATH_CONFIG: str = path.join(_PATH_HOME, ".config", "captura")


# NOTE: Paths within projects.
PATH_TESTS: str = path.join(PATH_BASE, "tests")
PATH_TESTS_ASSETS: str = path.join(PATH_TESTS, "assets")
PATH_SIMULATUS_ASSETS = path.join(PATH_SIMULATUS, "assets")


# =========================================================================== #
# Environment variables that have no configuration equivalent.


# ENV_DATA = []


def prefix_env(v: str) -> str:
    return f"{ENV_PREFIX}{v}"


def from_env(v: str, default: str | None = None, *, prefix: bool = True):
    envvar = prefix_env(v) if prefix else v
    w = environ.get(envvar, default)

    if w is None:
        msg = f"Could not determine value for environment variable `{w}`."
        raise ValueError(msg)
    return w


ENV_PREFIX = "CAPTURA_"
PATH_CONFIG_APP = from_env(
    "CONFIG_APP",
    Path.config("app.yaml"),
)
PATH_CONFIG_CLIENT = from_env(
    "CONFIG_CLIENT",
    Path.config("client.yaml"),
)
PATH_CONFIG_DUMMY = from_env(
    "CONFIG_DUMMY",
    Path.config("dummy.yaml"),
)
PATH_CONFIG_TEST_APP = from_env(
    "CONFIG_APP_TEST",
    Path.config("app.test.yaml"),
)
PATH_CONFIG_TEST_CLIENT = from_env(
    "CONFIG_CLIENT_TEST",
    Path.config("client.test.yaml"),
)
PATH_HOOKS: str = from_env(
    "HOOKS",
    path.join(PATH_BASE, "plugins/hooks.py"),
)
PATH_HOOKS_USE: bool = from_env("HOOKS_USE", "1") == "1"


PATH_STATIC = from_env("STATIC", Path.app("static"))
PATH_LOGS = from_env("LOGS", Path.base("logs"))
PATH_CONFIG_LOG = from_env("LOGS_CONFIG", Path.app("logging.yaml"))

PLUGINS_USE = from_env("PLUGINS_USE", "1") == "1"
VERBOSE = from_env("VERBOSE", "0") != "0"
VERBOSE_HTTPEXCEPTIONS = from_env("VERBOSE_HTTPEXCEPTIONS", "0") != "0"

# NOTE: Session secret ensures that middleware can reload the session properly.
SESSION_SECRET = from_env("SESSION_SECRET", secrets.token_urlsafe())


# =========================================================================== #
# Enum Stuff


def check_enum_opt_attr(
    cls: Type[Any],
    field: str,
    T_enum: Type[enum.Enum],
) -> None:
    if not hasattr(cls, field):
        msg = f"`{cls.__name__}` missing explicit `{field}`."
        raise AttributeError(msg)

    match getattr(cls, field, None):
        case T_enum() | None:  # type: ignore
            pass
        case bad:
            raise ValueError(
                f"`{cls.__name__}` has incorrect type for `{field}`."
                f"Expected `{T_enum}` or `None` (got `{bad}` of type "
                f"`{type(bad)}`)."
            )


# =========================================================================== sss
# LOGGING STUFF


# TODO: Add quehandler.
def setup_logging(config_path: str = PATH_CONFIG_LOG):
    with open(config_path, "r") as file:
        config = yaml.safe_load(file)

    logging.config.dictConfig(config)

    return config, logging.getLogger


DEFAULT_LOGGING_CONFIG, _get_logger = setup_logging()


def get_logger(name: str) -> logging.Logger:
    ll = _get_logger(name)
    return ll


CONSOLE_APP = Console()


def sql_render(session: Session, *qs) -> str:
    cmps = (
        f"{q.compile(session.bind, compile_kwargs=dict(literal_binds=True))};"
        for q in qs
    )
    cmp = "\n\n".join(cmps)
    return cmp


def sql(session: Session, *qs) -> None:
    cmp = sql_render(session, *qs)
    sql_syntax = Syntax(cmp, "mysql", theme="fruity", word_wrap=True)
    CONSOLE_APP.print(sql_syntax)
