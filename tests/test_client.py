import inspect
from typing import Any, Self

import httpx
from client.config import Config
from client.handlers import ConsoleHandler, Handler
from client.requests.base import BaseRequest


def test_base_request(client_config: Config):
    class FooHandler:
        status_code: int | None
        data: Any | None

        def __init__(self):
            self.status_code = None
            self.data = None

        async def __call__(
            self,
            res: httpx.Response,
            data: Any | None = None,
        ) -> httpx.Response:
            self.status_code = res.status_code
            self.data = data or res.json()

            return res

    class Req(BaseRequest):
        commands = ("read",)
        command = "test"

        async def read(self, foo: str, bar: str) -> httpx.Response:
            return httpx.Response(100)

    foo: Handler = FooHandler()
    req = Req(client_config, handler=foo)
    assert hasattr(req.read, "__call__")

    sig = inspect.signature(req.read)
    assert sig.return_annotation == httpx.Response
    assert "foo" in sig.parameters
    assert "bar" in sig.parameters
    assert len(sig.parameters) == 2
