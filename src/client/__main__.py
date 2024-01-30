from client import flags
from client.apply import ApplyMixins, ApplyMode, ApplyState
from client.config import Config
from client.handlers import Output
from client.requests import Requests


class It(Requests, ApplyMixins):
    commands = ("read", "apply", "destroy")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._state = None

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
        self._state = ApplyState(
            handler=self.handler,
            mode=ApplyMode.apply,
            requests=self,
        )


def test_it():
    import inspect

    # Inspect callback.
    sig = inspect.signature(It.callback)
    assert sig.return_annotation is None

    assert It.commands == ("read", "apply", "destroy")
    assert (output := sig.parameters.get("output")) is not None
    assert (columns := sig.parameters.get("columns")) is not None
    assert (profile := sig.parameters.get("profile")) is not None
    assert (host := sig.parameters.get("host")) is not None


test_it()


def main(_config: Config | None = None):
    config = _config or Config()  # type: ignore

    requests = It(config=config)

    typer = requests.typer
    typer()
