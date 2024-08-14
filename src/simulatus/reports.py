"""Database reports.

These were made because of dummies, but has uses in getting a 'big picture'
of the databases state. This will eventually be added as an extension to 
Captura.

Reports should be able to be saved, so this module defines 
:func:`create_tables` to create the optional reports tables.
"""

# =========================================================================== #
import enum
import itertools
import json
import secrets
from datetime import datetime
from typing import Annotated, Any, Dict, List, Tuple, TypeAlias

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field, TypeAdapter
from rich.align import Align
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
    update,
)
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship

# --------------------------------------------------------------------------- #
from captura import fields
from captura.depends import DependsSessionMaker
from captura.models import (
    Assignment,
    Base,
    Collection,
    Document,
    Event,
    Grant,
    MappedColumnUUID,
    User,
)
from captura.schemas import BaseSchema, TimespanLimitParams
from captura.views.base import BaseView


# NOTE: Schemas.
def row2dict(row):
    return {field: getattr(row, field) for field in row._fields}


class KindReport(str, enum.Enum):
    user = "user"
    aggregate = "aggregate"


ReportContentDataCountInt: TypeAlias = Annotated[int | None, Field(default=None)]


class ReportContentDataCount(BaseModel):
    users: ReportContentDataCountInt
    documents: ReportContentDataCountInt
    events: ReportContentDataCountInt
    collections: ReportContentDataCountInt
    grants: ReportContentDataCountInt
    assignments: ReportContentDataCountInt


class ReportContentData(BaseModel):
    count: ReportContentDataCount


class ReportContent(BaseModel):
    tags: Annotated[List[str], Field(default=list())]
    fn: Annotated[str | None, Field(default=None)]
    module: Annotated[str | None, Field(default=None)]
    data: ReportContentData


class ReportGrantSchema(BaseSchema):
    level: fields.FieldLevel
    pending_from: fields.FieldPendingFrom
    deleted: bool
    pending: bool
    count: int

    kind_mapped = None
    registry_exclude = True


class ReportGrantAggregateSchema(ReportGrantSchema):
    count_min: int | None
    count_max: int | None
    count_avg: float | None
    count_stddev: float | None


class BaseReportSchema(BaseSchema):
    note: str
    uuid_user: str | None
    uuid: str
    uuid_parent: str | None
    timestamp: datetime
    content: ReportContent

    kind_mapped = None
    registry_exclude = True

    def flatten(self) -> Dict[str, Any]:
        data = self.content.data
        count = data.count
        return dict(
            uuid_user=self.uuid_user,
            uuid=self.uuid,
            uuid_parent=self.uuid_parent,
            timestamp=self.timestamp,
            note=self.note,
            count_users=count.users,
            count_documents=count.documents,
            count_grants=count.grants,
            count_assignments=count.assignments,
            count_collections=count.collections,
            count_events=count.events,
        )

    def render_reports_grants(self) -> Panel:
        tt: Any
        if (reports_grants := getattr(self, "reports_grants", None)) is not None:
            tt = Table(title="Dummy Grants Report")
            cls = reports_grants[0].__class__

            for field in cls.model_fields:
                tt.add_column(field)

            for count, item in enumerate(reports_grants):
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

    def __rich__(self):
        if hasattr(self, "reports_grants"):
            panel_grants = self.render_reports_grants()
        else:
            panel_grants = None

        panel_report = self.render(align="left", exclude={"reports_grants", "user"})

        layout = Layout(visible=False)
        if panel_grants is not None:
            layout.split_row(
                Layout(panel_grants, name="left", visible=True),
                Layout(name="right"),
            )

        layout["right"].split_column(
            Layout(panel_report, name="top"),
            Layout(name="bottom", visible=False, ratio=3),
        )

        return layout


class ReportMinimalSchema(BaseReportSchema): ...


class ReportSchema(BaseReportSchema):
    reports_grants: List[ReportGrantAggregateSchema]


# --------------------------------------------------------------------------- #
# Models


class Report(Base):
    __tablename__ = "reports"

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
    )

    timestamp: Mapped[int] = mapped_column(
        default=lambda: datetime.timestamp(datetime.now())
    )

    # NOTE: Is it worth caching? Does anybody care?
    # NOTE: See `content`.
    _content: Mapped[Dict[str, Any]] = mapped_column(
        JSON(),
        nullable=True,
        name="content",
        # default=functools.cache(lambda: ReportContent().model_dump()),
    )
    note: Mapped[str] = mapped_column(String(256))

    uuid_user: Mapped[str] = mapped_column(String(16), nullable=True)
    reports_grants = relationship(
        "ReportGrant", back_populates="report", passive_deletes=True
    )

    @property
    def content(self) -> ReportContent:
        return ReportContent.model_validate(
            self._content if self._content is not None else dict()
        )

    @content.setter
    def content(self, v: Any) -> None:
        data = ReportContent.model_validate(v)
        self._content = data.model_dump(mode="json")

    # NOTE: This is for some jupyter fun, so no schema provided since this
    #       will likely be throw into a dataframe.
    @classmethod
    def q_flat(cls, *additional_fields):
        return select(
            User.id.label("id_user"),
            cls.uuid.label("uuid"),
            cls.uuid_parent.label("uuid_parent"),
            cls.uuid_user.label("uuid_user"),
            cls.timestamp.label("timestamp"),
            cls.timestamp.label("note"),
            *(
                func.JSON_EXTRACT(cls.content, f"$.data.count.{item}").label(
                    f"count_{item}"
                )
                for item in fields.KindObject
            ),
            *additional_fields,
        ).join(User)

    # NOTE: Labeled like ReportContentDataCount
    @classmethod
    def q_content_data_count(cls, user: User | None = None):
        q_user = select(func.count(User.uuid))
        q_document = select(func.count(Document.uuid))
        q_collection = select(func.count(Collection.uuid))
        q_event = select(func.count(Event.uuid))
        q_grant = select(func.count(Grant.uuid))
        q_assignment = select(func.count(Assignment.uuid))

        if user is not None:
            q_document = select(Grant.id_document).where(
                Grant.pending_from == fields.PendingFrom.created,
                Grant.id_user == user.id,
            )
            q_document = select(func.count()).select_from(q_document.subquery())
            q_collection = q_collection.join(User).where(User.uuid == user.uuid)
            q_assignment = q_assignment.join(Collection).where(
                Collection.id_user == user.id
            )
            q_grant = q_grant.where(Grant.id_user == user.id)
            q_event = select(func.count(Event.uuid)).where(Event.uuid_user == user.uuid)

        return select(
            q_user.label("users"),
            q_document.label("documents"),
            q_collection.label("collections"),
            q_event.label("events"),
            q_grant.label("grants"),
            q_assignment.label("assignments"),
        )


class ReportGrant(Base):
    __tablename__ = "reports_grants"

    uuid: Mapped[MappedColumnUUID] = mapped_column(primary_key=True)
    uuid_report: Mapped[MappedColumnUUID] = mapped_column(
        ForeignKey("reports.uuid", ondelete="CASCADE"),
        nullable=False,
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

    # NOTE: Should contain all of the columns specified in `ReportGrantSchema`.
    # NOTE: If mysl had `RETURNING` I'd use `INSERT INTO ... FROM SELECT ... RETURNING.
    @classmethod
    def q_select(cls, user: User | None = None):
        """Select the necessary data for a new grant."""

        _grant_agg = Grant.level, Grant.pending_from, Grant.deleted, Grant.pending
        q_reports_grants = (
            select(
                User.uuid.label("uuid_user"),
                Grant.level.label("level"),
                Grant.pending_from.label("pending_from"),
                Grant.pending.label("pending"),
                Grant.deleted.label("deleted"),
                func.count(Grant.uuid).label("count_per_user"),
            )
            .join(User)
            .group_by(User.uuid, *_grant_agg)
        )
        if user is not None:
            q_reports_grants = q_reports_grants.where(Grant.id_user == user.id)

        count_per_user: Any = literal_column("count_per_user")
        res_columns: Tuple[Any, ...] = (
            literal_column("level"),
            literal_column("pending_from"),
            literal_column("deleted"),
            literal_column("pending"),
        )

        q_grants = (
            select(
                *res_columns,
                func.min(count_per_user).label("count_min"),
                func.max(count_per_user).label("count_max"),
                func.avg(count_per_user).label("count_avg"),
                func.std(count_per_user).label("count_stddev"),
                func.sum(count_per_user).label("count"),
            )
            .select_from(q_reports_grants.subquery())
            .group_by(*res_columns)
            .order_by(*res_columns)
        )
        return q_grants


# =========================================================================== #
# Controllers


class ReportController:
    session: Session

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        note: str,
        user: User | None = None,
        *,
        uuid_parent: str | None = None,
        fn: str | None = None,
        module: str | None = None,
        tags: List[str] | None = None,
    ) -> Report:

        session = self.session
        reports_grants = list(
            ReportGrant(**row2dict(row))
            for row in session.execute(ReportGrant.q_select(user=user)).all()
        )

        (content_data_count,) = (
            ReportContentDataCount(**row2dict(row))
            for row in session.execute(Report.q_content_data_count(user=user))
        )

        content = ReportContent(
            fn=fn if fn is not None else "ReportsContoller.create",
            module=module if module is not None else "dummy.reports",
            tags=tags if tags is not None else ["api", "aggregate"],
            data=ReportContentData(count=content_data_count),
        )
        report = Report(
            note=note,
            reports_grants=reports_grants,
            uuid_parent=uuid_parent,
        )
        report.content = content
        return report

    def create_aggregate(self, note: str, tags: List[str] | None = None) -> Report:
        return self.create(note, tags=tags)

    def create_user(
        self,
        note: str,
        user: User,
        tags: List[str] | None = None,
        *,
        uuid_parent: str | None = None,
    ) -> Report:
        return self.create(note, user, uuid_parent=uuid_parent, tags=tags)

    # NOTE: Trying to avoid using json items in reads.
    def read(
        self,
        params: TimespanLimitParams,
        uuid_user: str | None = None,
        exclude_children: bool = True,
        kind_count: fields.KindObject | None = None,
        kind_count_desc: bool = True,
        tags: List[str] | None = None,
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
        if tags is not None:
            conds.append(
                func.JSON_OVERLAPS(
                    json.dumps(tags), func.JSON_VALUE(Report._content, "$.tags")
                )
            )

        q = select(Report).where(and_(*conds, true())).limit(params.limit)
        q = q.order_by(Report.timestamp.desc())
        if kind_count:
            _f = f"$.data.count.{kind_count.value}"
            f = func.JSON_EXTRACT(Report._content, _f)
            q = q.order_by(f.asc() if kind_count_desc else f.desc())

        # --------------------------------------------------------------------------- #
        from captura import util

        util.sql(self.session, q)

        return tuple(self.session.scalars(q))


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
    # @classmethod
    # def serial(cls, user: User | None, report: Report):
    #     if user is not None:
    #         return ReportUserSchema.model_validate(report)
    #     else:
    #         return ReportAggregateSchema.model_validate(report)

    @classmethod
    def post_report_build(
        cls,
        report_controller: DependsReportController,
        note: str,
        uuid_user: str | None = None,
        return_report: bool = False,
        tags: List[str] | None = None,
    ) -> ReportSchema | None:
        session = report_controller.session
        user = None
        if uuid_user is not None:
            user = session.scalar(select(User).where(User.uuid == uuid_user))

        report = report_controller.create(note, user, tags=tags)
        session.add(report)
        session.add_all(report.reports_grants)
        session.commit()
        session.refresh(report)
        if not return_report:
            return None

        return ReportSchema.model_validate(report)

    @classmethod
    def post_report_build_all(
        cls,
        report_controller: DependsReportController,
        note: str,
        tags: List[str] | None = None,
    ) -> str:
        session = report_controller.session

        uuid_report = secrets.token_urlsafe(8)
        report = report_controller.create_aggregate(note, tags=tags)
        report.uuid = uuid_report
        report.children = list(
            report_controller.create_user(
                note, user, tags=tags, uuid_parent=uuid_report
            )
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
        kind_count: fields.KindObject | None = None,
        kind_count_desc: bool = True,
        tags: List[str] | None = None,
    ) -> List[ReportMinimalSchema]:
        reports = report_controller.read(
            param,
            uuid_user,
            exclude_children=exclude_children,
            kind_count=kind_count,
            kind_count_desc=kind_count_desc,
            tags=tags,
        )

        return TypeAdapter(List[ReportMinimalSchema]).validate_python(reports)

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
    def get_report(
        cls, report_controller: DependsReportController, uuid_report: str
    ) -> ReportSchema:
        session = report_controller.session
        report = Report.if_exists(session, uuid_report)
        return ReportSchema.model_validate(report)

    @classmethod
    def put_report(
        cls,
        report_controller: DependsReportController,
        uuid_report: str,
        note: str | None = None,
        tags: str | None = None,
    ) -> None:
        if note is None and tags is None:
            raise HTTPException(422, detail="One of `note` or `tags` required.")

        session = report_controller.session
        report = Report.if_exists(session, uuid_report)
        if note is not None:
            report.note = note
        if tags is not None:

            _tags_args = (("$.tags", tag) for tag in tags)
            tags_args = itertools.chain(*_tags_args)
            content = func.JSON_ARRAY_APPEND(Report._content, *tags_args)
            q = update(Report).values(_content=content)
            q = q.where(Report.uuid == uuid_report)
            session.execute(q)

        session.add(report)
        session.commit()
