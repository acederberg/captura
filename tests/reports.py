# =========================================================================== #
from typing import Annotated, List, Optional, Self, override

import typer
from pydantic import BaseModel
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

# --------------------------------------------------------------------------- #
from app import fields, util
from app.models import Base, Collection, Document, Event, Grant, User
from app.schemas import BaseSchema, UserExtraSchema
from tests.config import PytestConfig
from tests.dummy import DummyHandler, DummyProvider


class ReportGrant(BaseModel):
    level: fields.FieldLevel
    pending_from: fields.FieldPendingFrom
    deleted: bool
    pending: bool
    count: int


class ReportGrantAggregate(ReportGrant):
    count_min: int
    count_max: int
    count_avg: float
    count_stddev: float


# --------------------------------------------------------------------------- #


class BaseReport(BaseSchema):
    reports_grants: List

    # reports_grants_cls: ClassVar[Type[ReportGrant]]
    kind_mapped = None
    registry_exclude = True

    def render_reports_grants(self) -> Panel:

        if self.reports_grants:
            tt = Table(title="Dummy Grants Report")
            cls = self.reports_grants[0].__class__

            for field in cls.model_fields:
                tt.add_column(field)

            for count, item in enumerate(self.reports_grants):
                style = "blue" if count % 2 else "cyan"
                if item.pending_from == fields.PendingFrom.created:
                    style = "on red"

                tt.add_row(
                    *(str(getattr(item, field)) for field in cls.model_fields),
                    style=style,
                )
        else:
            tt = "No grants to report."

        return Panel(
            Align.center(
                tt,
                vertical="middle",
            ),
        )

    @override
    def __rich__(self) -> Layout:
        panel_grants = self.render_reports_grants()
        panel_report = self.render(exclude={"reports_grants", "user"})

        layout = Layout(visible=False)
        layout.split_row(
            Layout(panel_grants, name="left"),
            Layout(name="right"),
        )
        layout["right"].split_column(
            Layout(panel_report, name="top"),
            Layout(name="bottom", visible=False, ratio=3),
        )

        return layout

    # def __rich__(self, rich_console: Console, options: ConsoleOptions) -> RenderResult:
    #     ...


class ReportUser(BaseReport):

    user: UserExtraSchema
    count_collections: int
    count_documents: int
    count_events: int

    reports_grants: List[ReportGrant]

    def __rich__(self) -> Layout:
        layout = super().__rich__()
        panel_user = self.user.render(exclude={"name", "description"})

        layout_right_bottom = layout["right"]["bottom"]
        layout_right_bottom.update(panel_user)
        layout_right_bottom.visible = True

        return layout

    @classmethod
    def create(
        cls,
        source: DummyProvider | User,
        session: Session | None = None,
    ) -> Self:

        match source:
            case User() as user:
                if session is None:
                    msg = "`session` is required when a user source is "
                    raise ValueError(msg + "provided.")
            case DummyProvider(session=Session() as session, user=User() as user):
                ...
            case bad:
                raise ValueError(f"Invalid source of kind `{type(bad)}`.")

        q_document_uuids = select(Grant.id_document).where(
            Grant.pending_from == PendingFrom.created,
            Grant.id_user == user.id,
        )

        n_documents = select(func.count()).select_from(q_document_uuids.subquery())
        n_collections = select(func.count(Collection.uuid)).where(
            Collection.id_user == user.id
        )
        n_events = select(func.count(Event.uuid)).where(Event.uuid_user == user.uuid)

        # ------------------------------------------------------------------ #

        _grant_agg = Grant.level, Grant.pending_from, Grant.deleted, Grant.pending
        q_reports_grants = (
            select(*_grant_agg, func.count(Grant.uuid).label("n_grants"))
            .where(Grant.id_user == user.id)
            .group_by(*_grant_agg)
            .order_by(*_grant_agg)
        )

        reports_grants = list(
            ReportGrant(
                level=grant.level,
                pending_from=grant.pending_from,
                pending=grant.pending,
                deleted=grant.deleted,
                count=grant.n_grants,
            )
            for grant in session.execute(q_reports_grants).all()
        )

        return mwargs(
            cls,
            user=user,
            count_collections=session.scalar(n_collections),
            count_documents=session.scalar(n_documents),
            count_events=session.scalar(n_events),
            reports_grants=reports_grants,
        )


class ReportAggregate:

    count_documents: int
    count_collections: int
    count_events: int
    count_users: int
    count_users_has_grants: int
    uuid_users_has_grants_not: Set[str]

    reports_grants: List[ReportGrantAggregate]

    @classmethod
    def create(cls, session: Session) -> Self:

        _grant_agg = Grant.level, Grant.pending_from, Grant.deleted, Grant.pending
        q_reports_grants = (
            select(
                User.uuid.label("uuid_user"),
                Grant.level.label("grant_level"),
                Grant.pending_from.label("grant_pending_from"),
                Grant.pending.label("grant_pending"),
                Grant.deleted.label("grant_deleted"),
                func.count(Grant.uuid).label("grant_count"),
            )
            .join(User)
            .group_by(User.uuid, *_grant_agg)
        )
        res_columns = (
            literal_column("grant_level"),
            literal_column("grant_pending_from"),
            literal_column("grant_deleted"),
            literal_column("grant_pending"),
        )

        grant_count = literal_column("grant_count")
        q_grants = (
            select(
                *res_columns,
                func.min(grant_count).label("grant_count_min"),
                func.max(grant_count).label("grant_count_max"),
                func.avg(grant_count).label("grant_count_avg"),
                func.std(grant_count).label("grant_count_stddev"),
                func.sum(grant_count).label("grant_count"),
            )
            .select_from(q_reports_grants.subquery())
            .group_by(*res_columns)
            .order_by(*res_columns)
        )

        reports_grants = list(
            ReportGrantAggregate(
                level=row.grant_level,
                pending_from=row.grant_pending_from,
                pending=row.grant_pending,
                deleted=row.grant_deleted,
                count=row.grant_count,
                count_min=row.grant_count_min,
                count_avg=row.grant_count_avg,
                count_stddev=row.grant_count_stddev,
                count_max=row.grant_count_max,
            )
            for row in session.execute(q_grants).all()
        )

        count_users = session.scalar(select(func.count(User.uuid)))
        assert count_users is not None

        q_users_has_grants = (
            q_count_users_has_grants := select(User.uuid.distinct())
            .join(Grant)
            .group_by(User.uuid)
            .having(func.count(Grant.uuid) > 0)
        )
        uuid_users_has_grants = set(session.scalars(q_users_has_grants))
        uuid_users_has_grants_not = set(
            session.scalars(
                select(User.uuid).where(User.uuid.not_in(q_count_users_has_grants))
            )
        )

        return mwargs(
            cls,
            count_documents=session.scalar(select(func.count(Document.uuid))),
            count_collections=session.scalar(select(func.count(Collection.uuid))),
            count_events=session.scalar(select(func.count(Event.uuid))),
            count_users=count_users,
            count_users_has_grants=len(uuid_users_has_grants),
            uuid_users_has_grants_not=uuid_users_has_grants_not,
            count_grants=session.scalar(select(func.count(Grant.uuid))),
            reports_grants=reports_grants,
        )


def context() -> typer.Context: ...


class CmdReport:
    commands = {"user", "aggregate"}

    @classmethod
    def user(cls, uuid: Optional[str] = None, new: bool = False):
        with dummy_handler.sessionmaker() as session:
            if not new:
                if uuid is None:
                    q = select(User).limit(1).order_by(func.random())
                else:
                    q = select(User).where(User.uuid == uuid)

                user = session.scalar(q)
                assert user is not None
            else:
                user = None

            dummy_provider = DummyProvider(
                dummy_handler.config,
                session,
                use_existing=user,
            )

            report = ReportUser.create(dummy_provider)

        console.print(report)

    @classmethod
    def aggregate(cls):
        with dummy_handler.sessionmaker() as session:
            report = ReportAggregate.create(session)

        console.print(report.render())


class CmdManage:
    @classmethod
    def dispose(
        cls,
        uuids: Annotated[Optional[List[str]], typer.Option("--uuid")] = None,
    ):
        console.print("[grenn]Cleaning up tainted data.")
        dummy_handler.dispose(set(uuids) if uuids is not None else None)
        console.print("[green]Done cleaning up.")

    @classmethod
    def restore(cls):
        console.print("[green]Restoring dummies...")
        dummy_handler.restore()
        console.print("[green]Done restoring dummies...")

    @classmethod
    def initialize(cls):
        with dummy_handler.sessionmaker() as session:
            Base.metadata.create_all(session.bind)


if __name__ == "__main__":

    config = PytestConfig()  # type: ignore
    engine = config.engine()
    sm = sessionmaker(engine)
    dummy_handler = DummyHandler(sm, config, user_uuids=list())

    tt = typer.Typer()
    tt.add_typer(report := typer.Typer(name="report"))
    tt.add_typer(mgmt := typer.Typer(name="manage"))

    console = Console()

    LOGGING_CONFIG, _get_logger = util.setup_logging(
        config.app.logging_configuration_path
    )
    logger = _get_logger(__name__)

    # logger.debug("terd")
    # logger.info("terd")
    # logger.warning("terd")
    # logger.critical("terd")
    # assert False
    tt()
