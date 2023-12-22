from os import path

PATH_BASE: str = path.realpath(path.join(path.dirname(__file__), "..", ".."))


class Path:
    @classmethod
    def base(cls, v: str) -> str:
        return path.join(PATH_BASE, v)
