# =========================================================================== #
import importlib
from typing import Annotated, Any, Dict, Optional

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


class ConfigCommands(BaseTyperizable):
    typer_check_verbage = False
    typer_decorate = False
    typer_commands = dict(profiles="profiles", hosts="hosts", show="show")
    typer_commands.update({"docker-host": "docker_host", "docker-db": "docker_mysql"})
    typer_children = dict()

    @classmethod
    def profiles(cls, _context: typer.Context) -> None:
        context = ContextData.resolve(_context)

        profiles = context.config.profiles
        context.console_handler.handle(
            data={pp: qq.model_dump(mode="json") for pp, qq in profiles.items()}
        )

        return

    @classmethod
    def hosts(cls, _context: typer.Context) -> None:
        context = ContextData.resolve(_context)

        hosts = context.config.hosts
        context.console_handler.handle(
            data={pp: qq.model_dump(mode="json") for pp, qq in hosts.items()}
        )

        return

    @classmethod
    def show(cls, _context: typer.Context) -> None:
        context = ContextData.resolve(_context)
        config = context.config
        profile = (
            None if config.profile is None else config.profile.model_dump(mode="json")
        )
        host = None if config.host is None else config.host.model_dump(mode="json")
        data = {config.use.profile: profile, config.use.host: host}
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
        amend: Annotated[
            Optional[str],
            typer.Option(
                "--amend",
                help="Configuration file to add to.",
            ),
        ] = None,
        amend_inplace: Annotated[
            bool,
            typer.Option(
                "--amend-inplace",
                help="Update configuration specified by `--amend`.",
            ),
        ] = False,
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
                        host=network_detail["IPAddress"],
                        remote=True,
                    )
                    for network_detail in networks.values()
                }
                if amend:
                    with open(amend, "r") as file:
                        config = Config.model_validate(yaml.safe_load(file))

                    config.hosts.update(hostconfs)
                    data = config.model_dump(
                        mode="json",
                        exclude={"profile", "host", "token"},
                    )
                    if amend_inplace:
                        for profile_name, profile in data["profiles"].items():
                            config.profiles[profile_name]
                            profile["token"] = config.profiles[
                                profile_name
                            ].token.get_secret_value()

                        console.print("[green]Updating client config.")
                        with open(amend, "w") as file:
                            yaml.dump(data, file)

                        raise typer.Exit()

                    console.print("# [green]Updated client config: ")
                    context.console_handler.handle(data=data)
                    return
                data = {k: v.model_dump(mode="json") for k, v in data.items()}

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
