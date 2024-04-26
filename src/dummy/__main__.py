# =========================================================================== #
import json
from functools import cached_property
from typing import Annotated, List, Optional, Self

import typer
import yaml
from fastapi import HTTPException
from pydantic import BaseModel
from rich.align import Align
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from sqlalchemy import func, select
from sqlalchemy.orm import session
from sqlalchemy.orm import sessionmaker as _sessionmaker

# --------------------------------------------------------------------------- #
from app import User
from app.auth import Token
from app.config import Config
from app.models import Base, Document
from app.schemas import TimespanLimitParams, UserExtraSchema, mwargs
from client.handlers import ConsoleHandler
from client.requests.base import BaseTyperizable, typerize
from dummy import DummyHandler, DummyProvider, DummyProviderYAML
from dummy.config import ConfigSimulatus, DummyConfig
from dummy.reports import (
    Report,
    ReportAggregateSchema,
    ReportController,
    ReportUserSchema,
    ReportView,
    pydantic_table,
    report_controller,
)

CONSOLE = Console()


class ContextDataDummy(BaseModel):
    quiet: bool = True
    config: ConfigSimulatus
    # console_handler: ConsoleHandler

    @cached_property
    def dummy_handler(self) -> DummyHandler:
        engine = self.config.engine()
        sm = _sessionmaker(engine)

        return DummyHandler(sm, self.config, user_uuids=list())

    @classmethod
    def for_typer(
        cls,
        context: typer.Context,
        quiet: Annotated[bool, typer.Option("--quiet/--loud")] = True,
        path_config: Annotated[Optional[str], typer.Option("--config")] = None,
    ) -> None:
        if path_config is None:
            config = mwargs(ConfigSimulatus)
        else:
            with open(path_config, "r") as file:
                config = ConfigSimulatus.model_validate(
                    yaml.safe_load(file),
                )

        context.obj = cls(config=config, quiet=quiet)


class CmdSnapshot(BaseTyperizable):
    """Server side snapshot."""

    typer_decorate = False
    typer_check_verbage = False
    typer_commands = dict(
        user="user",
        aggregate="aggregate",
        view="view",
        history="history",
        delete="delete",
        all="all",
        amend="amend",
    )

    @classmethod
    def delete(cls, _context: typer.Context, uuid_report: str):
        context: ContextDataDummy = _context.obj
        with context.dummy_handler.sessionmaker() as session:
            try:
                ReportView.delete_report(
                    ReportController(session),
                    uuid_report,
                )
            except HTTPException as err:
                print(err)
                raise typer.exit(1)

    @classmethod
    def view(cls, _context: typer.Context, uuid_report: str):
        context: ContextDataDummy = _context.obj
        with context.dummy_handler.sessionmaker() as session:
            try:
                report = ReportView.read_report(
                    ReportController(session),
                    uuid_report,
                )
            except HTTPException as err:
                print(err)
                raise typer.Exit(1)

        CONSOLE.print(report)

    @classmethod
    def amend(
        cls,
        _context: typer.Context,
        uuid_report: str,
        note: Annotated[str, typer.Option("--note")],
    ):
        context: ContextDataDummy = _context.obj
        with context.dummy_handler.sessionmaker() as session:
            try:
                ReportView.update_report(
                    ReportController(session),
                    uuid_report,
                    note,
                )
            except HTTPException as err:
                print(err)
                raise typer.Exit(1)

    @classmethod
    def history(
        cls,
        _context: typer.Context,
        uuid_user: Optional[str] = None,
        before: Optional[int] = None,
        after: Optional[int] = None,
        limit: int = 10,
    ):
        context: ContextDataDummy = _context.obj
        with context.dummy_handler.sessionmaker() as session:
            reports = ReportView.get_reports(
                ReportController(session),
                TimespanLimitParams(before=before, after=after, limit=limit),
                uuid_user,
            )

            if not reports:
                CONSOLE.print("[green]No reports to show.")
                raise typer.Exit(0)

            tt = pydantic_table(reports)
            CONSOLE.print(tt)
            # report, *_ = reports
            # tt = Table()
            # for

    @classmethod
    def all(
        cls,
        _context: typer.Context,
        note: Optional[str] = None,
    ):
        note = note or "From `CmdSnapshot.all`."
        context: ContextDataDummy = _context.obj
        with context.dummy_handler.sessionmaker() as session:
            if not context.quiet:
                CONSOLE.print("[green]Building aggregate and user reports.")

            uuid_report = ReportView.post_report_build_all(
                ReportController(session),
                note,
            )

        if not context.quiet:
            CONSOLE.print("report_uuid", uuid_report)

    @classmethod
    def user(
        cls,
        _context: typer.Context,
        uuid: Optional[str] = None,
        note: Optional[str] = None,
    ):
        context: ContextDataDummy = _context.obj
        with context.dummy_handler.sessionmaker() as session:
            if uuid is not None:
                q = select(User).where(User.uuid == uuid)
                user = session.scalar(q)
                if user is None:
                    CONSOLE.print(f"No user with uuid `{uuid}`.")
                    raise typer.Exit(1)
            else:
                dummy_provider = DummyProvider(
                    context.dummy_handler.config,
                    session,
                    use_existing=None,
                )
                user = dummy_provider.user

            report = ReportView.post_report_build(
                ReportController(session),
                note=note or "From `CmdSnapshot.user`.",
                uuid_user=user.uuid,
                return_report=context.quiet,
            )

        if not context.quiet:
            CONSOLE.print(report)

    @classmethod
    def aggregate(
        cls,
        _context: typer.Context,
        note: Optional[str] = None,
    ):
        context: ContextDataDummy = _context.obj
        with context.dummy_handler.sessionmaker() as session:
            report = ReportView.post_report_build(
                ReportController(session),
                note=note or "From `CmdSnapshot.aggregate`.",
                uuid_user=None,
                return_report=not context.quiet,
            )

        if not context.quiet:
            CONSOLE.print(report)


class CmdDummy(BaseTyperizable):
    typer_decorate = False
    typer_check_verbage = False
    typer_commands = dict()
    typer_children = dict(snapshot=CmdSnapshot)

    typer_commands = dict(
        dispose="dispose",
        restore="restore",
        init="initialize",
        spawn="spawn",
        taint="taint",
        reset="reset",
    )

    @classmethod
    def dispose(
        cls,
        _context: typer.Context,
        uuids: Annotated[Optional[List[str]], typer.Option("--uuid")] = None,
        preview: bool = False,
    ):
        context: ContextDataDummy = _context.obj

        if not preview:
            CONSOLE.print("[grenn]Cleaning up tainted data.")
            context.dummy_handler.dispose(set(uuids) if uuids is not None else None)
            CONSOLE.print("[green]Done cleaning up.")
            return

        with context.dummy_handler.sessionmaker() as session:
            users = session.scalars(context.dummy_handler.q_clean())
            dumped = json.dumps(
                [
                    UserExtraSchema.model_validate(user).model_dump(
                        mode="json", include={"uuid", "content"}
                    )
                    for user in users
                ]
            )

        CONSOLE.print(Panel(Align.left(JSON(dumped))))

    @classmethod
    def restore(cls, _context: typer.Context):
        context: ContextDataDummy = _context.obj

        CONSOLE.print("[green]Restoring dummies...")
        with context.dummy_handler.sessionmaker() as session:
            DummyProviderYAML.merge(session)

        context.dummy_handler.restore()
        CONSOLE.print("[green]Done restoring dummies.")

    @classmethod
    def spawn(cls, _context: typer.Context, count: int = 1):
        context: ContextDataDummy = _context.obj
        handler = context.dummy_handler
        with handler.sessionmaker() as session:
            for _ in range(count):
                DummyProvider(handler.config, session, use_existing=None)

    @classmethod
    def taint(cls, _context: typer.Context, count: int = 1, uuid: Optional[str] = None):
        context: ContextDataDummy = _context.obj
        handler = context.dummy_handler
        with handler.sessionmaker() as session:
            if uuid is not None:
                q = select(User).where(User.uuid == uuid)
            else:
                q = select(User).order_by(func.random()).limit(count)

            users = tuple(session.scalars(q))
            for user in users:
                DummyProvider(
                    context.config,
                    session,
                    use_existing=user,
                ).info_mark_tainted()

            dumped = json.dumps(
                [
                    UserExtraSchema.model_validate(user).model_dump(
                        mode="json", exclude={"name", "description"}
                    )
                    for user in users
                ]
            )
            session.commit()

            CONSOLE.print(Panel(Align.left(JSON(dumped))))

    @classmethod
    def initialize(cls, _context: typer.Context):
        context: ContextDataDummy = _context.obj

        with context.dummy_handler.sessionmaker() as session:
            Base.metadata.create_all(session.bind)
            DummyProviderYAML.merge(session)

    @classmethod
    def reset(cls, _context: typer.Context):
        """Reset without destroying reports."""

        context: ContextDataDummy = _context.obj

        with context.dummy_handler.sessionmaker() as session:
            users = session.scalars(select(User))
            documents = session.scalars(select(Document))

            for items in (users, documents):
                for item in items:
                    session.delete(item)

            session.commit()


def main():
    tt = typerize(CmdDummy, callback=ContextDataDummy.for_typer)
    tt()
