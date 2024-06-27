# =========================================================================== #
import importlib
from typing import Annotated, Any, Dict, List, Optional

import typer
import yaml
from pydantic import SecretStr

# --------------------------------------------------------------------------- #
from app import util
from app.schemas import mwargs
from client import flags, hooks
from client.config import Config, HostConfig, ProfileConfig
from client.handlers import CONSOLE, ConsoleHandler, HandlerData
from client.requests import Requests
from client.requests.assignments import AssignmentRequests
from client.requests.base import BaseRequests, BaseTyperizable, ContextData, params
from client.requests.collections import CollectionRequests
from client.requests.documents import DocumentRequests
from client.requests.grants import GrantRequests
from client.requests.tokens import TokenRequests
from client.requests.users import UserRequests

if util.PATH_HOOKS_USE:
    hooks.do_hooks(Requests)


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
ArgumentProfileName = Annotated[
    str, typer.Argument(help="Name of the profile to update.")
]
FlagProfileCurrent = Annotated[
    bool, typer.Option("--current/--all", help="Show the current profile.")
]
FlagProfileNames = Annotated[
    Optional[List[str]],
    typer.Option("--name", help="Names to filter by."),
]
FlagHostCurrent = Annotated[
    bool,
    typer.Option(
        "--current/--all",
        help="Show the current host.",
    ),
]
FlagHostNames = Annotated[
    Optional[List[str]],
    typer.Option("--name", help="Names to filter by."),
]
FlagTokenRequired = Annotated[str, typer.Option()]
FlagUUIDUser = Annotated[str, typer.Option()]


class ProfilesCommand(BaseTyperizable):

    typer_check_verbage = False
    typer_decorate = False
    typer_commands = dict(
        list="list", remove="remove", set="set", add="add", ls="list", rm="remove"
    )

    @classmethod
    def require_profile(
        cls,
        context: ContextData,
        config: Config | None = None,
    ) -> ProfileConfig:
        config = config if config is not None else context.config
        if config.profile is None:
            context.console_handler.console.print("[red]No profile to update.")
            raise typer.Exit(1)

        return config.profile

    @classmethod
    def handle_out(
        cls,
        context: ContextData,
        config: Config,
        *,
        show: bool = True,
        config_path_out: FlagConfigOut = None,
    ):
        if config_path_out is not None:
            context.console_handler.console.print("[green]Updating profile...")
            config.dump(config_path_out)
        elif not show:
            return
        else:
            context.console_handler.handle(
                handler_data=HandlerData(
                    data=config.model_dump_minimal(),
                    output_config=context.config.output,
                )
            )

    @classmethod
    def add(
        cls,
        _context: typer.Context,
        name: ArgumentProfileName,
        *,
        token: FlagTokenRequired,
        uuid: FlagUUIDUser,
        config_path: FlagConfig = None,
        config_path_out: FlagConfigOut = None,
    ):
        context = ContextData.resolve(_context)

        config = context.get_config(config_path)
        if name in config.profiles:
            context.console_handler.console.print(
                f"[red]Profile with name {name} already exists."
            )
            raise typer.Exit(0)

        config.profiles[name] = mwargs(ProfileConfig, uuid_user=uuid, token=token)
        cls.handle_out(context, config, config_path_out=config_path_out)

    @classmethod
    def set(
        cls,
        _context: typer.Context,
        name: ArgumentProfileName,
        *,
        token: flags.FlagTokenOptional = None,
        uuid: flags.FlagUUIDUserOptional = None,
        config_path: FlagConfig = None,
        config_path_out: FlagConfigOut = None,
    ):
        context = ContextData.resolve(_context)

        config = context.get_config(config_path)
        profile = cls.require_profile(context, config)

        if token is not None:
            profile.token = SecretStr(token)
        if uuid is not None:
            profile.uuid_user = uuid

        config.profiles[name] = profile
        cls.handle_out(context, config, show=False, config_path_out=config_path_out)

    @classmethod
    def remove(
        cls,
        _context: typer.Context,
        name: ArgumentProfileName,
        *,
        config_path: FlagConfig = None,
        config_path_out: FlagConfigOut = None,
    ):
        context = ContextData.resolve(_context)
        config = context.get_config(config_path)

        if name not in config.profiles:
            context.console_handler.console.print(f"[red]No such profile `{name}`.")
            raise typer.Exit(0)

        config.profiles.pop(name)
        cls.handle_out(context, config, config_path_out=config_path_out)

    @classmethod
    def list(
        cls,
        _context: typer.Context,
        *,
        current: FlagProfileCurrent = False,
        names: FlagProfileNames = None,
    ) -> None:
        """To set a ``profile``, see the ``use`` subcommand."""

        context = ContextData.resolve(_context)

        profiles = context.config.profiles
        data = tuple()

        if current:
            if names:
                CONSOLE.print("[red]Names cannot be specified when `--current` is.")
                raise typer.Exit(1)

            profile = cls.require_profile(context)
            data = (
                (
                    context.config.use.profile,
                    profile.model_dump(mode="json") if profile else profile,
                ),
            )
        else:
            data = ((pp, qq.model_dump(mode="json")) for pp, qq in profiles.items())
            if names is not None:
                data = ((pp, qq) for pp, qq in data if pp in names)

        context.console_handler.handle(
            handler_data=HandlerData(
                data=dict(data),
                output_config=context.config.output,
            )
        )

        return


class HostCommand(BaseTyperizable):
    typer_check_verbage = False
    typer_decorate = False
    typer_commands = dict(list="list")

    @classmethod
    def list(
        cls,
        _context: typer.Context,
        current: FlagHostCurrent = False,
        names: FlagHostNames = None,
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

        context.console_handler.handle(
            handler_data=HandlerData(
                data=dict(data),
                output_config=context.config.output,
            )
        )
        return


class DockerCommand(BaseTyperizable):
    typer_check_verbage = False
    typer_decorate = False
    typer_commands = dict(server="server", db="db")

    @classmethod
    def server(
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

                data = config.model_dump(
                    mode="json", exclude={"profile", "host", "token"}
                )
                context.console_handler.handle(
                    handler_data=HandlerData(
                        data=data,
                        output_config=context.config.output,
                    )
                )
                return

        context.console_handler.handle(
            handler_data=HandlerData(
                data=data,
                output_config=context.config.output,
            )
        )

    @classmethod
    def db(cls, _context: typer.Context):
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
        context.console_handler.handle(
            handler_data=HandlerData(
                data=data,
                output_config=context.config.output,
            )
        )


class ConfigCommands(BaseTyperizable):
    typer_check_verbage = False
    typer_decorate = False
    typer_commands = dict(show="show", use="use")
    typer_children = dict(hosts=HostCommand, profiles=ProfilesCommand)

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
        config = context.get_config(config_path)

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
            context.console_handler.handle(data=config.model_dump_minimal())
            raise typer.Exit(0)

        context.console_handler.console.print("[green]Updating client config.")
        config.dump(config_path_out)

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
            output=config.output.model_dump(mode="json"),
        )
        context.console_handler.handle(
            handler_data=HandlerData(
                data=data,
                output_config=context.config.output,
            )
        )


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
