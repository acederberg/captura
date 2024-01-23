import inspect
from client.util import BaseRequest
import httpx
from client.config import Config


def test_base_request(client_config: Config):
    class Req(BaseRequest):
        commands = ("read",)
        command = "test"

        def read(self, foo: str, bar: str) -> httpx.Response:
            ...

    # if not isinstance(Req.read, property):
    #     msg = "`read` should be transformed into a function property."
    #     raise ValueError(msg)
    # assert len(Req.fns) == 1

    req = Req(client_config)
    assert hasattr(req.read, "__call__")

    assert print(inspect.signature(req.read))
