# =========================================================================== #
import json
from datetime import datetime
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
from sqlalchemy import delete, func, select
from sqlalchemy.orm import session
from sqlalchemy.orm import sessionmaker as _sessionmaker

# --------------------------------------------------------------------------- #
from app import User
from app.auth import Token
from app.config import Config
from app.models import Base, Document
from app.schemas import TimespanLimitParams, UserExtraSchema, mwargs
from client.config import Output, OutputConfig
from client.handlers import ConsoleHandler, HandlerData
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

# --------------------------------------------------------------------------- #
# Flags

FlagNote = Annotated[
    str,
    OPTION_NOTE := typer.Option(
        "--note",
        help="Note associated with a report.",
    ),
]
FlagNoteOptional = Annotated[Optional[str], OPTION_NOTE]
FlagBefore = Annotated[Optional[int], typer.Option("--before")]
FlagAfter = Annotated[Optional[int], typer.Option("--after")]
FlagLimit = Annotated[
    int,
    typer.Option(
        "--limit",
        "-n",
        help="Maximum number of reports to display.",
    ),
]
FlagUUIDUserOptional = Annotated[
    Optional[str],
    typer.Option(
        "--uuid-user",
        help="UUID of the report subject. When this is ``None``, aggregate reports are created.",
    ),
]
FlagUUIDUserListOptional = Annotated[
    Optional[List[str]], typer.Option("--uuid-user", help="User uuids.")
]

FlagCount = Annotated[
    int, typer.Option("--count", help="Number of dummies to generate/taint.")
]
FlagManifest = Annotated[
    Optional[str],
    typer.Option(
        "--manifest",
        "-f",
        help="Dummy configuration to overwrite that specified by the config.",
    ),
]
FlagManifestPreview = Annotated[
    bool,
    typer.Option("--preview", help="Manifest preview (as YAML)."),
]

ArgUUIDReport = Annotated[str, typer.Argument(help="Report UUID.")]


class ContextDataDummy(BaseModel):
    # NOTE: Global options for flags do not exist. Instead, create a manifest.
    quiet: bool = True
    config: ConfigSimulatus
    config_output: OutputConfig

    def register_manifest(self, manifest_path: str | None) -> DummyConfig | None:
        if manifest_path is None:
            return

        manifest = DummyConfig.load(manifest_path)
        self.config.dummy = manifest

        return manifest

    def preview_manifest(self):
        data = HandlerData(
            data=self.config.dummy.model_dump(),
            output_config=self.config_output,
        )
        data.print()

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

        config_output = mwargs(OutputConfig, output=Output.yaml)
        context.obj = cls(config=config, quiet=quiet, config_output=config_output)


# --------------------------------------------------------------------------- #
# Typerizables


class CmdReport(BaseTyperizable):
    """Reports management."""

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
    def delete(cls, _context: typer.Context, uuid_report: ArgUUIDReport):
        """Delete one report."""

        context: ContextDataDummy = _context.obj
        with context.dummy_handler.sessionmaker() as session:
            try:
                ReportView.delete_report(
                    ReportController(session),
                    uuid_report,
                )
            except HTTPException as err:
                print(err)
                raise typer.Exit(1)

    @classmethod
    def view(cls, _context: typer.Context, uuid_report: ArgUUIDReport):
        """View *(in detail)* a report."""

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
    def amend(cls, _context: typer.Context, uuid_report: ArgUUIDReport, note: FlagNote):
        """Update a note on a report."""

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
        uuid_user: FlagUUIDUserOptional = None,
        before: FlagBefore = None,
        after: FlagAfter = None,
        limit: FlagLimit = 10,
    ):
        """View the latest reports."""

        context: ContextDataDummy = _context.obj
        tsp = mwargs(TimespanLimitParams, before=before, after=after, limit=limit)
        with context.dummy_handler.sessionmaker() as session:
            reports = ReportView.get_reports(ReportController(session), tsp, uuid_user)

            if not reports:
                CONSOLE.print("[green]No reports to show.")
                raise typer.Exit(0)

            tt = pydantic_table(reports)
            CONSOLE.print(tt)

    @classmethod
    def all(
        cls,
        _context: typer.Context,
        note: FlagNoteOptional = None,
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
        uuid: FlagUUIDUserOptional = None,
        note: FlagNoteOptional = None,
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
        note: FlagNoteOptional = None,
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


class CmdUser(BaseTyperizable):
    """Manage dummy users."""

    typer_decorate = False
    typer_check_verbage = False
    typer_commands = dict(new="new", get="get", taint="taint")

    @classmethod
    def new(cls, _context: typer.Context, count: FlagCount = 1):
        """Spawn one (or more when ``--count`` is specified)."""
        context: ContextDataDummy = _context.obj
        handler = context.dummy_handler
        with handler.sessionmaker() as session:
            for _ in range(count):
                DummyProvider(handler.config, session, use_existing=None)

    @classmethod
    def get(cls, _context: typer.Context, count: FlagCount = 1):
        """Get one (or more when ``--count`` is specified). The intended use
        of this is as a tool to debug any strangeness with pytest fixtures.
        """
        context: ContextDataDummy = _context.obj
        handler = context.dummy_handler
        with handler.sessionmaker() as session:
            q_existing = select(User).order_by(func.random()).limit(count)
            existing = session.scalars(q_existing)
            for ee in existing:
                DummyProvider(handler.config, session, use_existing=ee)

    @classmethod
    def taint(
        cls,
        _context: typer.Context,
        count: FlagCount = 1,
        uuid: FlagUUIDUserOptional = None,
    ):
        """Taint one (or more when ``--count`` is specified)."""
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

            if not context.quiet:
                CONSOLE.print(Panel(Align.left(JSON(dumped))))


class CmdDummy(BaseTyperizable):
    """Manage Captura dummy data and create reports."""

    typer_decorate = False
    typer_check_verbage = False
    typer_commands = dict(
        preview="preview",
        dispose="dispose",
        apply="apply",
        destroy="destroy",
        initialize="initialize",
    )
    typer_children = dict(reports=CmdReport, users=CmdUser)

    @classmethod
    def dispose(
        cls,
        _context: typer.Context,
        manifest: FlagManifest = None,
        uuids: FlagUUIDUserListOptional = None,
        preview: FlagManifestPreview = False,
    ):
        """Dispose of all tainted dummies. To clear the database, see
        ``destroy``.
        """
        context: ContextDataDummy = _context.obj
        context.register_manifest(manifest)
        if preview:
            context.preview_manifest()
            return

        CONSOLE.print("[grenn]Cleaning up tainted data.")
        context.dummy_handler.dispose(set(uuids) if uuids is not None else None)
        CONSOLE.print("[green]Done cleaning up.")
        return

        # with context.dummy_handler.sessionmaker() as session:
        #     users = session.scalars(context.dummy_handler.q_clean())
        #     dumped = json.dumps(
        #         [
        #             UserExtraSchema.model_validate(user).model_dump(
        #                 mode="json", include={"uuid", "content"}
        #             )
        #             for user in users
        #         ]
        #     )
        #
        # CONSOLE.print(Panel(Align.left(JSON(dumped))))

    @classmethod
    def apply(
        cls,
        _context: typer.Context,
        manifest: FlagManifest = None,
        preview: FlagManifestPreview = False,
    ):
        """Create dummies to meet the criteria specified in config. To view the
        config, see ``config``.
        """

        context: ContextDataDummy = _context.obj
        context.register_manifest(manifest)
        if preview:
            context.preview_manifest()
            return

        from rich.progress import Progress

        CONSOLE.print("[green]Restoring dummies...")
        with context.dummy_handler.sessionmaker() as session:
            DummyProviderYAML.merge(session)

        start = datetime.now()
        with Progress() as progress:
            t = progress.add_task(description="Dummies Generated")
            context.dummy_handler.restore(
                callback=lambda dd, count, n: progress.update(
                    t,
                    advance=1,
                    total=n,
                )
            )
        end = datetime.now()

        CONSOLE.print("[green]Done restoring dummies.")
        CONSOLE.print(f"[green]Total time: {end - start}")

    @classmethod
    def initialize(cls, _context: typer.Context):
        """Add the tables required for reports to the database."""

        context: ContextDataDummy = _context.obj

        with context.dummy_handler.sessionmaker() as session:
            Base.metadata.create_all(session.bind)
            DummyProviderYAML.merge(session)

    @classmethod
    def destroy(
        cls,
        _context: typer.Context,
        destroy_reports: Annotated[
            bool,
            typer.Option(
                "--destroy-reports",
                help="When true, the reports table is emptied.",
            ),
        ] = False,
    ):
        """Empty all tables."""

        context: ContextDataDummy = _context.obj

        with context.dummy_handler.sessionmaker() as session:
            # NOTE: Using delete directly to avoid memory overhead. Relations
            #       are configured on the database side and not on this side
            #       using ``FOREIGN KEY ... ON DELETE CASCADE``.
            session.execute(delete(User))
            session.execute(delete(Document))
            if destroy_reports:
                session.execute(delete(Report))

            session.commit()

    @classmethod
    def preview(cls, _context: typer.Context, manifest_path: FlagManifest = None):
        context: ContextDataDummy = _context.obj
        context.register_manifest(manifest_path)
        context.preview_manifest()


def main():
    tt = typerize(CmdDummy, callback=ContextDataDummy.for_typer)
    tt()
