# =========================================================================== #
import importlib
from typing import Annotated, Any, Dict, List, Optional

import typer
import yaml

# --------------------------------------------------------------------------- #
from client.config import Config, HostConfig
from client.handlers import CONSOLE, ConsoleHandler
from client.requests import Requests
from client.requests.assignments import AssignmentRequests
from client.requests.base import BaseRequests, BaseTyperizable, ContextData, params
from client.requests.collections import CollectionRequests
from client.requests.documents import DocumentRequests
from client.requests.grants import GrantRequests
from client.requests.tokens import TokenRequests
from client.requests.users import UserRequests

FlagConfigOut = Annotated[
    Optional[str],
    typer.Option(
        "--config-out",
        "-o",
        help=(
            "Create/overwrite specified configuration file with output that "
            "would go the terminal (minus secret seconsoring)."
        ),
    ),
]
FlagConfig = Annotated[
    Optional[str],
    typer.Option(
        "--config",
        help=(
            "Configuration file to add to and load from. Overwrites the "
            "global `--config` option. To specify output, see `--config-out` "
            "if it is provided."
        ),
    ),
]


class ConfigCommands(BaseTyperizable):
    typer_check_verbage = False
    typer_decorate = False
    typer_commands = dict(profiles="profiles", hosts="hosts", show="show")
    typer_commands.update(
        {
            "docker-host": "docker_host",
            "docker-db": "docker_mysql",
            "use": "use",
        }
    )
    typer_children = dict()

    @classmethod
    def use(
        cls,
        _context: typer.Context,
        host: Annotated[
            Optional[str],
            typer.Option("--host", "-h"),
        ] = None,
        profile: Annotated[
            Optional[str],
            typer.Option("--profile", "-p"),
        ] = None,
        config_path: FlagConfig = None,
        config_path_out: FlagConfigOut = None,
    ):
        context = ContextData.resolve(_context)

        if config_path is not None:
            with open(config_path, "r") as file:
                config = Config.model_validate(yaml.safe_load(file))
        else:
            config = context.config

        if host is not None:
            if host not in config.hosts:
                msg = f"[red]No such host `{host}` in client config."
                CONSOLE.print(msg.format(host))
                raise typer.Exit(1)
            config.use.host = host

        if profile is not None:
            if profile not in config.profiles:
                msg = f"[red]No such profile `{profile}` in client config."
                CONSOLE.print(msg.format(host))
                raise typer.Exit(1)
            config.use.profile = profile

        if config_path_out is None:
            context.console_handler.handle(
                data=config.model_dump(
                    mode="json",
                    exclude={"profile", "host", "token"},
                )
            )
            raise typer.Exit(0)

        context.console_handler.console.print("[green]Updating client config.")
        data = config.model_dump_config()
        with open(config_path_out, "w") as file:
            yaml.dump(data, file)

            raise typer.Exit(0)

    @classmethod
    def profiles(
        cls,
        _context: typer.Context,
        current: Annotated[
            bool, typer.Option("--current", help="Show the current host.")
        ],
        names: Annotated[
            Optional[List[str]],
            typer.Option("--name", help="Names to filter by."),
        ] = None,
    ) -> None:
        """To set a ``profile``, see the ``use`` subcommand."""

        context = ContextData.resolve(_context)

        profiles = context.config.profiles
        data = tuple()

        if current:
            if names:
                CONSOLE.print("[red]Names cannot be specified when `--current` is.")
                raise typer.Exit(1)

            profile = context.config.profile
            data = (
                (
                    context.config.use.profile,
                    profile.model_dump(mode="json") if profile is not None else profile,
                ),
            )
        else:
            data = ((pp, qq.model_dump(mode="json")) for pp, qq in profiles.items())
            if names is not None:
                data = ((pp, qq) for pp, qq in data if pp in names)

        context.console_handler.handle(data=dict(data))

        return

    @classmethod
    def hosts(
        cls,
        _context: typer.Context,
        current: Annotated[
            bool,
            typer.Option(
                "--current/--all",
                help="Show the current host.",
            ),
        ] = True,
        names: Annotated[
            Optional[List[str]],
            typer.Option("--name", help="Names to filter by."),
        ] = None,
    ) -> None:
        """To set a ``host``, see the ``use`` subcommand."""
        context = ContextData.resolve(_context)

        hosts = context.config.hosts
        if current and names is None:
            host = context.config.host
            data = (
                (
                    context.config.use.host,
                    host.model_dump(mode="json") if host is not None else host,
                ),
            )
        else:
            data = ((pp, qq.model_dump(mode="json")) for pp, qq in hosts.items())
            if names is not None:
                data = ((pp, qq) for pp, qq in data if pp in names)

        context.console_handler.handle(data=dict(data))
        return

    @classmethod
    def show(cls, _context: typer.Context) -> None:
        context = ContextData.resolve(_context)
        config = context.config
        profile = (
            None if config.profile is None else config.profile.model_dump(mode="json")
        )
        host = None if config.host is None else config.host.model_dump(mode="json")
        data = dict(
            profile={config.use.profile: profile},
            host={config.use.host: host},
        )
        context.console_handler.handle(data=data)

    @classmethod
    def docker_host(
        cls,
        _context: typer.Context,
        inspect: Annotated[
            bool,
            typer.Option(
                "-i",
                "--inspect",
                help="Display docker inspect results. Has priority over `--ips`.",
            ),
        ] = False,
        ips: Annotated[
            bool,
            typer.Option(
                "--ips",
                help="Display IPS from docker inspect results.",
            ),
        ] = False,
        config_path: FlagConfig = None,
        config_path_out: FlagConfigOut = None,
    ) -> None:
        import docker

        context = ContextData.resolve(_context)
        console = context.console_handler.console

        client = docker.DockerClient()
        if (container := client.containers.get("captura-server")) is None:
            console.print("[red]Docker compose project is not running.")
            raise typer.Exit(1)

        res = client.api.inspect_container(container.name)

        data: Dict[str, Any]
        match (inspect, ips):
            case (True, _):
                data = res
            case (_, True):
                networks = res["NetworkSettings"]["Networks"]
                data = {
                    network_name: network_detail["IPAddress"]
                    for network_name, network_detail in networks.items()
                }
            case _:
                networks = res["NetworkSettings"]["Networks"]
                hostconfs = {
                    "docker": HostConfig(
                        host="http://" + network_detail["IPAddress"] + ":8080",
                        remote=True,
                    )
                    for network_detail in networks.values()
                }
                if config_path:
                    with open(config_path, "r") as file:
                        config = Config.model_validate(yaml.safe_load(file))
                else:
                    config = context.config

                config.hosts.update(hostconfs)

                if config_path_out:
                    console.print("[green]Updating client config.")
                    with open(config_path_out, "w") as file:
                        data = config.model_dump_config()
                        yaml.dump(data, file)

                    raise typer.Exit()

                console.print("# [green]Updated client config: ")
                data = config.model_dump(
                    mode="json", exclude={"profile", "host", "token"}
                )
                context.console_handler.handle(data=data)
                return

        context.console_handler.handle(data=data)

    @classmethod
    def docker_mysql(cls, _context: typer.Context):
        import docker

        context = ContextData.resolve(_context)
        console = context.console_handler.console

        client = docker.DockerClient()
        if (container := client.containers.get("captura-db")) is None:
            console.print("[red]Docker compose project is not running.")
            raise typer.Exit(1)

        res = client.api.inspect_container(container.name)
        networks = res["NetworkSettings"]["Networks"]
        data = {
            network_name: network_detail["IPAddress"]
            for network_name, network_detail in networks.items()
        }
        context.console_handler.handle(data=data)


__all__ = (
    "AssignmentRequests",
    "BaseRequests",
    "ContextData",
    "params",
    "CollectionRequests",
    "DocumentRequests",
    "GrantRequests",
    "TokenRequests",
    "UserRequests",
    "ConsoleHandler",
    "CONSOLE",
    "Requests",
    "Config",
)
