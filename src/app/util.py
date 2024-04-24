# =========================================================================== #
import enum
import logging
import logging.config
import logging.handlers
from os import environ, path
from typing import Any, Type

import yaml
from rich.console import Console
from rich.syntax import Syntax
from sqlalchemy.orm import Session

ENV_PREFIX = "CAPTURA_"
VERBOSE = environ.get(f"{ENV_PREFIX}VERBOSE")
VERBOSE_HTTPEXCEPTIONS = environ.get(f"{ENV_PREFIX}VERBOSE-HTTPEXCEPTIONS")
LOG_LEVEL = logging.INFO

# =========================================================================== #
# PATH STUFF


class Path:
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
    def docker(cls, v: str) -> str:
        return path.join(PATH_DOCKER, v)

    @classmethod
    def config(cls, v: str) -> str:
        return path.join(PATH_CONFIG, v)


PATH_BASE: str = path.realpath(path.join(path.dirname(__file__), "..", ".."))
PATH_APP: str = path.join(PATH_BASE, "src/app")
PATH_CLIENT: str = path.join(PATH_BASE, "src/client")
PATH_CONFIG: str = path.join(PATH_BASE, "configs")
PATH_DOCKER: str = path.join(PATH_BASE, "docker")
PATH_TESTS: str = path.join(PATH_BASE, "tests")
PATH_TESTS_ASSETS: str = environ.get(ENV_PREFIX + "CONFIG_PATH") or path.join(
    PATH_TESTS, "assets"
)

PATH_CONFIG_APP = Path.config("app.yaml")
PATH_CONFIG_CLIENT = Path.config("client.yaml")
PATH_CONFIG_TEST_APP = Path.config("app.test.yaml")
PATH_CONFIG_TEST_CLIENT = Path.config("client.test.yaml")


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
        case T_enum() | None:
            pass
        case bad:
            raise ValueError(
                f"`{cls.__name__}` has incorrect type for `{field}`."
                f"Expected `{T_enum}` or `None` (got `{bad}` of type "
                f"`{type(bad)}`)."
            )


# =========================================================================== sss
# LOGGING STUFF


ENV_LOG_CONFIG = f"{ENV_PREFIX}LOG_CONFIG"
PATH_LOG_CONFIG = environ.get(ENV_LOG_CONFIG, Path.base("logging.yaml"))


# TODO: Add quehandler.
def setup_logging(config_path: str = PATH_LOG_CONFIG):
    with open(config_path, "r") as file:
        config = yaml.safe_load(file)

    logging.config.dictConfig(config)

    return config, logging.getLogger


DEFAULT_LOGGING_CONFIG_PATH = Path.base("logging.yaml")
DEFAULT_LOGGING_CONFIG, _get_logger = setup_logging(DEFAULT_LOGGING_CONFIG_PATH)


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
