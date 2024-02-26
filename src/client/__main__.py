from typing import Annotated, List, Optional

import httpx
import typer

from client import flags
# from client.apply import ApplyMixins, ApplyMode, ApplyState, apply
from client.config import Config
from client.handlers import Output
from client.requests import Requests
from client.requests.base import params


class It(Requests): 

    commands_check_verbage = False
    commands = ("routes", )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._state = None

    async def routes(
        self, 
        methods: Annotated[List[str] | None, typer.Option()] = None,
        names: Annotated[List[str] | None, typer.Option()] = None,
        names_fragment: Annotated[Optional[str], typer.Option] = None,
        paths_fragment: Annotated[Optional[str], typer.Option] = None,
    ) -> httpx.Response:
        return await self.client.get(
            "/routes",
            params=params(
                methods=methods, 
                names=names,
                names_fragment=names_fragment,
                paths_fragment=paths_fragment,
            ),
            headers=self.headers,
        )

    def callback(
        self,
        output: flags.FlagOutput = Output.table,
        columns: flags.FlagColumns = list(),
        *,
        profile: flags.FlagProfile = None,
        host: flags.FlagHost = None,
    ) -> None:
        super().callback(output, columns, profile=profile, host=host)
        assert self.handler is not None
        self.handler.column_configs = {
            "path": {"justify": "left", "style": typer.colors.CYAN},
            "methods": {"justify": "left", "style": typer.colors.BRIGHT_CYAN},
            "name": {"justify": "left", "style": typer.colors.CYAN},
        }
        self.handler.columns = ("path", "methods", "name", )
        # self._state = ApplyState(
        #     handler=self.handler,
        #     mode=ApplyMode.apply,
        #     requests=self,
        # )

    # def apply(
    #     self, filepath: flags.ArgFilePath, mode: ApplyMode = ApplyMode.read
    # ) -> None:
    #
    #     self.state.mode = mode
    #     apply(self, self.state, filepath)


# def test_it():
#     import inspect
#
#     # Inspect callback.
#     sig = inspect.signature(It.callback)
#     assert sig.return_annotation is None
#
#     assert It.commands == ("read", "apply", "destroy")
#     assert (output := sig.parameters.get("output")) is not None
#     assert (columns := sig.parameters.get("columns")) is not None
#     assert (profile := sig.parameters.get("profile")) is not None
#     assert (host := sig.parameters.get("host")) is not None
#
#
# test_it()
#


def main(_config: Config | None = None):
    config = _config or Config()  # type: ignore

    it = It(config=config)

    typer = it.typer

    # typer.command("apply")(it.apply)

    typer()
