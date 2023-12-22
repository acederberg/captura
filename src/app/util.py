from os import path

PATH_BASE: str = path.realpath(path.join(path.dirname(__file__), '..', '..'))

class path:


    @classmethod
    def base(cls) -> str:
