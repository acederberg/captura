import logging
from os import path

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
PATH_TESTS: str = path.join(PATH_BASE, "tests")
PATH_TESTS_ASSETS: str = path.join(PATH_TESTS, "assets")


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
