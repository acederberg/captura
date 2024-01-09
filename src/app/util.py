import logging
from os import environ
from os import path

ENV_PREFIX = "ARTICLES_"

# =========================================================================== #
# LOGGING STUFF


def get_logger(name: str) -> logging.Logger:
    ll = logging.getLogger(name)

    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    ll.addHandler(handler)

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(name)s - %(message)s"
    )
    handler.setFormatter(formatter)

    ll.setLevel(logging.DEBUG)
    return ll


# =========================================================================== #
# PATH STUFF

PATH_BASE: str = path.realpath(path.join(path.dirname(__file__), "..", ".."))
PATH_CONFIG: str = path.join(PATH_BASE, "configs")
PATH_DOCKER: str = path.join(PATH_BASE, "docker")
PATH_TESTS: str = path.join(PATH_BASE, "tests")
PATH_TESTS_ASSETS: str = environ.get(ENV_PREFIX + "CONFIG_PATH") or path.join(
    PATH_TESTS, "assets"
)


class Path:
    @classmethod
    def base(cls, v: str) -> str:
        return path.join(PATH_BASE, v)

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


PATH_CONFIG_APP = Path.config("app.yaml")
PATH_CONFIG_CLIENT = Path.config("client.yaml")
PATH_CONFIG_TEST_APP = Path.config("app.test.yaml")
PATH_CONFIG_TEST_CLIENT = Path.config("client.test.yaml")
