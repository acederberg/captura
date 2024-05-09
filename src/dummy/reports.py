"""Reports should be able to be saved, so this module defines 
:func:`create_tables` to create the optional reports tables.
"""

# =========================================================================== #
import enum
from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional, Self, Set, Tuple

import typer
from fastapi import Depends
from pydantic import BaseModel, TypeAdapter
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from sqlalchemy import (
    JSON,
    Enum,
    ForeignKey,
    String,
    and_,
    func,
    literal_column,
    select,
    true,
)
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship, sessionmaker

# --------------------------------------------------------------------------- #
from app import fields, util
from app.depends import DependsSessionMaker, DependsTokenAdmin
from app.models import (
    Assignment,
    Base,
    Collection,
    Document,
    Event,
    Grant,
    MappedColumnUUID,
    User,
)
from app.schemas import (
    AsOutput,
    BaseSchema,
    TimespanLimitParams,
    UserExtraSchema,
    mwargs,
)
from app.views.base import BaseView

# Models


class KindReport(str, enum.Enum):
    user = "user"
    aggregate = "aggregate"


class Report(Base):
    __tablename__ = "reports"
    # __tablediff__ = {
    #     "count_users",
    #     "count_collections",
    #     "count_documents",
    #     "count_events",
    #     "count_grants",
    #     "count_assignments",
    # }

    uuid: Mapped[MappedColumnUUID] = mapped_column(primary_key=True)
    uuid_parent: Mapped[str] = mapped_column(
        ForeignKey(uuid, ondelete="CASCADE"),
        nullable=True,
    )

    # NOTE: For `snapshot all` because an aggregate report might have
    #       supporting user reports generated alongside it.
    children: Mapped[List["Report"]] = relationship(
        "Report",
        foreign_keys=uuid_parent,
        cascade="delete, all",
    )

    timestamp: Mapped[int] = mapped_column(
        default=lambda: datetime.timestamp(datetime.utcnow())
    )
    content: Mapped[Dict[str, Any]] = mapped_column(JSON(), nullable=True)
    note: Mapped[str] = mapped_column(String(256))

    uuid_user: Mapped[str] = mapped_column(String(16), nullable=True)
    count_users: Mapped[int | None]
    count_collections: Mapped[int]
    count_documents: Mapped[int]
    count_events: Mapped[int]
    count_grants: Mapped[int]
    count_assignments: Mapped[int]

    reports_grants = relationship("ReportGrant", back_populates="report")


class ReportGrant(Base):
    __tablename__ = "reports_grants"
    __tablediff__ = {"count", "count_avg", "count_stddev"}

    uuid: Mapped[MappedColumnUUID] = mapped_column(primary_key=True)
    uuid_report: Mapped[MappedColumnUUID] = mapped_column(
        ForeignKey("reports.uuid", ondelete="CASCADE")
    )

    report = relationship("Report")

    level: Mapped[fields.Level] = mapped_column(Enum(fields.Level))
    pending: Mapped[bool] = mapped_column(default=True)
    pending_from: Mapped[fields.PendingFrom] = mapped_column(Enum(fields.PendingFrom))
    deleted: Mapped[bool]

    count: Mapped[int]
    count_avg: Mapped[float | None]
    count_stddev: Mapped[float | None]
    count_min: Mapped[int | None]
    count_max: Mapped[int | None]


# =========================================================================== #
# Controllers


class ReportController:
    session: Session

    def __init__(self, session: Session):
        self.session = session

    def create_aggregate(self, note: str) -> Report:
        session = self.session
        _grant_agg = Grant.level, Grant.pending_from, Grant.deleted, Grant.pending
        q_reports_grants = (
            select(
                User.uuid.label("uuid_user"),
                Grant.level.label("level"),
                Grant.pending_from.label("pending_from"),
                Grant.pending.label("pending"),
                Grant.deleted.label("deleted"),
                func.count(Grant.uuid).label("count"),
            )
            .join(User)
            .group_by(User.uuid, *_grant_agg)
        )
        res_columns = (
            literal_column("level"),
            literal_column("pending_from"),
            literal_column("deleted"),
            literal_column("pending"),
        )

        count = literal_column("count")
        q_grants = (
            select(
                *res_columns,
                func.min(count).label("count_min"),
                func.max(count).label("count_max"),
                func.avg(count).label("count_avg"),
                func.std(count).label("count_stddev"),
                func.sum(count).label("count_"),
            )
            .select_from(q_reports_grants.subquery())
            .group_by(*res_columns)
            .order_by(*res_columns)
        )

        reports_grants = list(
            ReportGrant(
                level=row.level,
                pending_from=row.pending_from,
                pending=row.pending,
                deleted=row.deleted,
                count=row.count_,
                count_min=row.count_min,
                count_avg=row.count_avg,
                count_stddev=row.count_stddev,
                count_max=row.count_max,
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
        uuid_users_has_grants_not = tuple(
            session.scalars(
                select(User.uuid).where(User.uuid.not_in(q_count_users_has_grants))
            )
        )

        return Report(
            note=note,
            count_documents=session.scalar(select(func.count(Document.uuid))),
            count_collections=session.scalar(select(func.count(Collection.uuid))),
            count_events=session.scalar(select(func.count(Event.uuid))),
            count_users=count_users,
            content=dict(
                count_users_has_grants=len(uuid_users_has_grants),
                uuid_users_has_grants_not=uuid_users_has_grants_not,
            ),
            count_grants=session.scalar(select(func.count(Grant.uuid))),
            count_assignments=session.scalar(select(func.count(Assignment.uuid))),
            reports_grants=reports_grants,
        )

    def create_user(
        self,
        note: str,
        user: User,
    ) -> Report:
        session = self.session
        q_document_uuids = select(Grant.id_document).where(
            Grant.pending_from == fields.PendingFrom.created,
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

        n_grants = sum(map(lambda item: item.count, reports_grants))
        n_assignments = (
            select(func.count(Assignment.uuid))
            .join(Collection)
            .where(Collection.id_user == user.id)
        )

        return Report(
            note=note,
            uuid_user=user.uuid,
            count_collections=session.scalar(n_collections),
            count_documents=session.scalar(n_documents),
            count_events=session.scalar(n_events),
            count_grants=n_grants,
            count_assignments=session.scalar(n_assignments),
            reports_grants=reports_grants,
        )

    # NOTE: Trying to avoid using json items in reads.
    def read(
        self,
        params: TimespanLimitParams,
        uuid_user: str | None = None,
        exclude_children: bool = True,
    ) -> Tuple[Report, ...]:
        """Returns aggregate results be default. Otherwise returns user
        results when :param:`uuid_user` is not ``None``."""

        conds = []
        if params.after_timestamp is not None:
            conds.append(params.after_timestamp <= Report.timestamp)

        if params.before_timestamp is not None:
            conds.append(Report.timestamp <= params.before_timestamp)

        if uuid_user is not None:
            conds.append(Report.uuid_user == uuid_user)

        if exclude_children:
            conds.append(Report.uuid_parent.is_(None))

        q = select(Report).where(and_(*conds, true())).limit(params.limit)
        q = q.order_by(Report.timestamp.desc())

        return tuple(self.session.scalars(q))


#     def diffs(
#         self,
#         reports: Tuple[Report, ...],
#     ) -> Tuple[ReportDiffSchema, ...]:
#
#         if len(reports) < 2:
#             return tuple()
#
#         return tuple(a, b in zip(reports[:-1], reports[0:]))
#
#
# class ReportDiffSchema(BaseSchema):
#
#     uuid_report_left: str
#     uuid_report_right: str
#
#     timestamp: int
#     count: Dict[str, Any]
#
#     @classmethod
#     def create(cls, left: Report | ReportGrant,


# =========================================================================== #
# Schemas


class ReportGrantSchema(BaseSchema):
    level: fields.FieldLevel
    pending_from: fields.FieldPendingFrom
    deleted: bool
    pending: bool
    count: int

    kind_mapped = None
    registry_exclude = True


class ReportGrantAggregateSchema(ReportGrantSchema):
    count_min: int
    count_max: int
    count_avg: float
    count_stddev: float


# --------------------------------------------------------------------------- #


def pydantic_table(items) -> Table | Panel:
    if not items:
        return Panel(Align.center("No results to display."))

    cls = items[0].__class__
    tt = Table()
    for field in cls.model_fields:
        tt.add_column(field)

    for count, item in enumerate(items):
        style = "blue" if count % 2 else "cyan"
        tt.add_row(
            *(str(getattr(item, field)) for field in cls.model_fields),
            style=style,
        )

    return tt


class BaseReportSchema(BaseSchema):
    note: str
    uuid_user: str | None
    uuid: str
    uuid_parent: str | None
    timestamp: datetime
    count_collections: int
    count_documents: int
    count_events: int
    count_grants: int
    count_assignments: int

    kind_mapped = None
    registry_exclude = True


class ReportRich:
    reports_grants: List

    def render_reports_grants(self) -> Panel:
        tt: Table | str
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

    def __rich__(self) -> Layout:
        panel_grants = self.render_reports_grants()
        panel_report = self.render(align="left", exclude={"reports_grants", "user"})

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


class ReportUserMinimalSchema(BaseReportSchema): ...


class ReportUserSchema(ReportRich, ReportUserMinimalSchema):
    user: UserExtraSchema
    reports_grants: List[ReportGrantSchema]

    def __rich__(self) -> Layout:
        layout = super().__rich__()
        panel_user = self.user.render(align="left", exclude={"name", "description"})

        layout_right_bottom = layout["right"]["bottom"]
        layout_right_bottom.update(panel_user)
        layout_right_bottom.visible = True

        return layout


class ReportAggregateMinimalSchema(BaseReportSchema):
    count_users: int


class ReportAggregateSchema(ReportRich, BaseReportSchema):
    reports_grants: List[ReportGrantAggregateSchema]
    content: Dict[str, Any]


# =========================================================================== #
# Views


def report_controller(sessionmaker: DependsSessionMaker):
    with sessionmaker() as session:
        yield ReportController(session)


DependsReportController = Annotated[
    ReportController,
    Depends(report_controller),
]


class ReportView(BaseView):
    @classmethod
    def serial(cls, user: User | None, report: Report):
        if user is not None:
            return mwargs(ReportUserSchema, user=user, **vars(report))
        else:
            return ReportAggregateSchema.model_validate(report)

    @classmethod
    def post_report_build(
        cls,
        report_controller: DependsReportController,
        note: str,
        uuid_user: str | None = None,
        return_report: bool = False,
    ) -> ReportUserSchema | ReportAggregateSchema | None:
        if uuid_user is not None:
            user = User.if_exists(report_controller.session, uuid_user)
            report = report_controller.create_user(note, user)
        else:
            user = None
            report = report_controller.create_aggregate(note)

        session = report_controller.session
        session.add(report)
        session.add_all(report.reports_grants)
        session.commit()

        session.refresh(report)

        if not return_report:
            return None

        return cls.serial(user, report)

    @classmethod
    def post_report_build_all(
        cls, report_controller: DependsReportController, note: str
    ) -> str:
        session = report_controller.session

        report = report_controller.create_aggregate(note)
        report.children = list(
            report_controller.create_user(note, user)
            for user in session.scalars(select(User))
        )
        session.add(report)
        session.commit()

        session.refresh(report)
        return report.uuid

    @classmethod
    def get_reports(
        cls,
        report_controller: DependsReportController,
        param: TimespanLimitParams,
        uuid_user: str | None = None,
        exclude_children: bool = True,
    ) -> List[ReportUserMinimalSchema] | List[ReportAggregateMinimalSchema]:
        reports = report_controller.read(
            param, uuid_user, exclude_children=exclude_children
        )

        SS = ReportUserMinimalSchema if uuid_user else ReportAggregateMinimalSchema
        return TypeAdapter(List[SS]).validate_python(reports)

    @classmethod
    def delete_report(
        cls, report_controller: DependsReportController, uuid_report: str
    ):
        session = report_controller.session
        report = Report.if_exists(session, uuid_report)
        session.delete(report)
        session.commit()

        return None

    @classmethod
    def read_report(
        cls, report_controller: DependsReportController, uuid_report: str
    ) -> ReportUserSchema | ReportAggregateSchema:
        session = report_controller.session
        report = Report.if_exists(session, uuid_report)
        user = session.scalar(select(User).where(User.uuid == report.uuid_user))

        return cls.serial(user, report)

    @classmethod
    def update_report(
        cls,
        report_controller: DependsReportController,
        uuid_report: str,
        note: str,
    ) -> None:
        session = report_controller.session
        report = Report.if_exists(session, uuid_report)
        report.note = note
        session.add(report)
        session.commit()
