# import abc
import enum
import secrets
from datetime import datetime
from logging import warn
from typing import (Annotated, Any, Callable, Dict, Generator, Generic, List,
                    Literal, Self, Set, Tuple, Type, TypeAlias, TypeVar,
                    overload)

from fastapi import HTTPException, status
from sqlalchemy import (CTE, BinaryExpression, BooleanClauseList, Column,
                        ColumnClause, ColumnElement, CompoundSelect, Enum,
                        ForeignKey, Index, Select, String, UniqueConstraint,
                        and_, func, literal_column, select, text, true, union,
                        union_all)
from sqlalchemy.dialects import mysql
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import (DeclarativeBase, InstrumentedAttribute, Mapped,
                            Session, backref, column_property, mapped_column,
                            object_session, relationship)
from sqlalchemy.orm.mapped_collection import attribute_keyed_dict
from sqlalchemy.sql import false

from app import __version__, util

# =========================================================================== #
# CONSTANTS, ENUMS, ETC.
#
# NOTE: These enums will be used throughout the program and a should be used
#       to create the types needed by fastapi and typer.
#


UUIDSplit = Tuple[Set[str], Set[str]]
LENGTH_NAME: int = 96
LENGTH_TITLE: int = 128
LENGTH_DESCRIPTION: int = 256
LENGTH_URL: int = 256
LENGTH_MESSAGE: int = 1024
LENGTH_CONTENT: int = 2**15
LENGTH_FORMAT: int = 8


class Level(enum.Enum):
    # NOTE: Must be consisten with sql, indexes start at 1
    view = 1
    modify = 2
    own = 3


class LevelStr(str, enum.Enum):
    view = "view"
    modify = "modify"
    own = "own"


class LevelHTTP(enum.Enum):
    DELETE = Level.own
    PUT = Level.modify
    POST = Level.modify
    PATCH = Level.modify
    GET = Level.view


class KindEvent(str, enum.Enum):
    create = "create"
    upsert = "upsert"
    update = "update"
    delete = "delete"
    grant = "grant"
    restore = "restore"


class PendingFrom(str, enum.Enum):
    created = 3
    granter = 2
    grantee = 1


# NOTE: This maps table names to their corresponding API names. It is important
#       to note that this uses singular names and not plural names.
class KindObject(str, enum.Enum):
    user = "users"
    document = "documents"
    collection = "collections"
    edit = "edits"
    event = "events"
    assignment = "_assocs_collections_documents"
    grant = "_assocs_users_documents"


class Plural(str, enum.Enum):
    user = "users"
    document = "documents"
    collection = "collections"
    edit = "edits"
    event = "events"
    assignment = "assignments"
    grant = "grants"


class Singular(str, enum.Enum):
    users = "user"
    documents = "document"
    collections = "collection"
    edits = "edit"
    assignments = "assignment"
    grants = "grant"


class KindRecurse(str, enum.Enum):
    depth_first = "depth-first"
    bredth_first = "bredth_first"


class ChildrenUser(str, enum.Enum):
    collections = "collections"
    documents = "documents"
    edits = "edits"


class ChildrenCollection(str, enum.Enum):
    documents = "documents"
    edits = "edits"


class ChildrenDocument(str, enum.Enum):
    edits = "edits"


class ChildrenAssignment(str, enum.Enum):
    documents = "documents"
    collections = "collections"


class ChildrenGrant(str, enum.Enum):
    documents = "documents"
    users = "users"


# NOTE: Indexing is important as it is how the front end will get most data.
#       This is done to keep relationships opaque (by keeping the primary keys
#       out of the users views) and to avoid having to specify multiple primary
#       keys for some resources (e.g. `AssocUserDocument`). See
#
#       .. code::
#
#           https://dev.mysql.com/doc/refman/8.0/en/mysql-indexes.html
#


MappedColumnUUID = Annotated[
    str,
    mapped_column(
        String(16),
        default=lambda: secrets.token_urlsafe(8),
        index=True,
    ),
]

uuid = (
    mapped_column(String(16), default=lambda: secrets.token_urlsafe(8), index=True),
)
MappedColumnDeleted = Annotated[bool, mapped_column(default=False)]

# =========================================================================== #
# Models and MixinsIndex column sqlalchemy


class Base(DeclarativeBase):
    uuid: Mapped[MappedColumnUUID]
    deleted: Mapped[MappedColumnDeleted]

    # NOTE: Only `classmethod`s should need session due to `object_session`.

    # ----------------------------------------------------------------------- #
    # Finders.
    @classmethod
    def if_exists(
        cls, session: Session, uuid: str, status: int = 404, msg=None
    ) -> Self:
        m = session.execute(select(cls).where(cls.uuid == uuid)).scalar()
        if m is None:
            msg = msg if msg is not None else "Object does not exist."
            kind = KindObject(cls.__tablename__).name
            detail = dict(uuid_obj=uuid, msg=msg, kind_obj=kind)
            raise HTTPException(status, detail=detail)
        return m

    @classmethod
    def if_many(
        cls,
        session: Session,
        uuid: Set[str],
        callback: Callable[[Self], Self] | None = None,
    ) -> Tuple[Self, ...]:
        res = session.execute(select(cls).where(cls.uuid.in_(uuid))).scalars()
        if callback is not None:
            res = (callback(item) for item in res)

        return tuple(res)

    # ----------------------------------------------------------------------- #
    # Resolvers

    ResolvableSelfSingular: TypeAlias = Self | str
    ResolvableSelfMultiple: TypeAlias = Tuple[Self, ...] | Set[str]
    ResolvableSelf: TypeAlias = ResolvableSelfSingular | ResolvableSelfMultiple

    @overload
    @classmethod
    def resolve(cls, session: Session, that: ResolvableSelfSingular) -> Self: ...

    @overload
    @classmethod
    def resolve(
        cls, session: Session, that: ResolvableSelfMultiple
    ) -> Tuple[Self, ...]: ...

    @classmethod
    def resolve(cls, session: Session, that: ResolvableSelf) -> Self | Tuple[Self, ...]:
        """Provided :param:`that` which is any reasonable representation of
        a(n) instance(s), return the associated instance(s).
        """
        match that:
            case tuple():
                return that
            case cls():  # type: ignore
                return that
            case str():
                return cls.if_exists(session, that)
            case set():
                return cls.if_many(session, that)
            case _ as bad:
                raise ValueError(f"Invalid identifier `{bad}`.")

    @overload
    @classmethod
    def resolve_uuid(
        cls,
        session: Session,
        that: ResolvableSelfMultiple,
    ) -> Set[str]: ...

    @overload
    @classmethod
    def resolve_uuid(
        cls,
        session: Session,
        that: ResolvableSelfSingular,
    ) -> str: ...

    @classmethod
    def resolve_uuid(
        cls,
        session: Session,
        that: ResolvableSelf,
    ) -> str | Set[str]:

        data: Self | Tuple[Self, ...]
        match data := cls.resolve(session, that):
            case cls():
                return data.uuid
            case tuple():
                return set(item.uuid for item in data)
            case set() | str():
                return data
            case _ as bad:
                raise ValueError(f"Invalid identifier `{bad}`.")

    # ----------------------------------------------------------------------- #
    # Rest

    @classmethod
    def q_uuid(cls, uuids: set[str]):
        return select(cls).where(cls.uuid.in_(uuids))

    def get_session(self) -> Session:
        session = object_session(self)
        if session is None:
            detail = dict(
                uuid=self.uuid,
                kind=KindObject._value2member_map_[self.__tablename__].name,
                msg="Could not find session.",
            )
            raise HTTPException(500, detail=detail)
        return session

    def check_not_deleted(
        self,
        status_code: int = 410,
        # deleted: bool = True,
    ) -> Self:
        if self.deleted:
            detail = dict(
                msg="Object is deleted.",
                uuid_obj=self.uuid,
                kind_obj=KindObject(self.__tablename__).name,
            )
            raise HTTPException(status_code, detail=detail)
        return self


class PrimaryTableMixins:
    """Creation and deletion data will go into the table associated with
    :class:`Event`.
    """

    # uuid: Mapped[MappedColumnUUID]
    public: Mapped[bool] = mapped_column(default=True)
    # deleted: Mapped[bool] = mapped_column(default=False)

    @classmethod
    def q_select_ids(cls, uuids: Set[str]) -> Select:
        match (id := getattr(cls, "id", None)):
            case Column() | InstrumentedAttribute():
                return select(id).where(cls.uuid.in_(uuids))
            case None:
                raise AttributeError(
                    f"Table `{cls.__name__}` must have an `id` `column` to use"
                    "`q_select_ids`."
                )
            case _:
                tt = type(id)
                raise ValueError(f"`id` must be of type `Column`, got `{tt}`.")

    @classmethod
    def q_conds(
        cls,
        uuids: Set[str] | None,
        exclude_deleted: bool = True,
        *,
        conds: BooleanClauseList | ColumnElement[bool] | None = None,
    ) -> ColumnElement[bool] | None:
        items = [conds] if conds is not None else []
        if exclude_deleted:
            items.append(cls.deleted == false())
        if uuids is not None:
            items.append(cls.uuid.in_(uuids))
        return and_(*items) if len(items) else None

    @classmethod
    def q_conds_public(
        cls,
        uuids: Set[str] | None = None,
        exclude_deleted: bool = True,
    ) -> ColumnElement[bool]:
        conds = cls.public == true()
        return cls.q_conds(uuids, exclude_deleted, conds=conds)  # type: ignore


class SearchableTableMixins(PrimaryTableMixins):
    name: Mapped[str]
    description: Mapped[str]

    @classmethod
    def q_select_public(
        cls, uuids: Set[str] | None = None, exclude_deleted: bool = True
    ):
        q = select(cls).where(cls.q_conds_public(uuids, exclude_deleted))
        return q

    @classmethod
    def q_search_conds(
        cls,
        name_like: str | None = None,
        description_like: str | None = None,
        conds=None,
    ):
        fmt = "^.*{}.*$"
        items = [conds] if conds is not None else []
        if name_like is not None:
            items.append(cls.name.regexp_match(fmt.format(name_like)))
        if description_like is not None:
            items.append(cls.description.regexp_match(fmt.format(description_like)))
        return and_(*items)

    @classmethod
    def q_search(
        cls,
        user_uuid: str | None,
        uuids: Set[str] | None = None,
        exclude_deleted: bool = True,
        *,
        all_: bool = True,
        name_like: str | None = None,
        description_like: str | None = None,
        session=None,
    ):
        if not all_ and user_uuid is None:
            raise ValueError("`all_` must be true when a user is not provided.")
        q = None
        if user_uuid:
            q = cls.q_select_for_user(user_uuid, uuids, exclude_deleted)
        r = None
        if all_:
            r = cls.q_select_public(uuids, exclude_deleted)

        search_conds = cls.q_search_conds(name_like, description_like)
        items = tuple(
            p.where(search_conds) if search_conds is not None else p
            for p in (q, r)
            if p is not None
        )
        if not len(items):
            raise ValueError()

        return union(*items)

    @classmethod
    def q_select_for_user(
        cls,
        user_uuid: str,
        uuids: Set[str] | None,
        exclude_deleted: bool = True,
    ) -> Select: ...


# =========================================================================== #
# Mapped


class Event(Base):
    # NOTE: Would it make more sence to record updates, creations, and
    #       deletions inside of an events table instead? It would be easy to
    #       track the objects by their UUID

    __tablename__ = "events"

    timestamp: Mapped[int] = mapped_column(
        default=(_now := lambda: datetime.timestamp(datetime.now())),
    )

    # id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    uuid: Mapped[MappedColumnUUID] = mapped_column(primary_key=True)
    uuid_parent: Mapped[str] = mapped_column(
        ForeignKey("events.uuid"),
        nullable=True,
    )
    children: Mapped[List["Event"]] = relationship("Event", foreign_keys=uuid_parent)

    uuid_undo: Mapped[str | None] = mapped_column(ForeignKey("events.uuid"))
    undo: Mapped["Event"] = relationship("Event", foreign_keys=uuid_undo)

    uuid_user: Mapped[str] = mapped_column(ForeignKey("users.uuid"))
    user: Mapped["User"] = relationship()

    uuid_obj: Mapped[MappedColumnUUID]
    api_origin: Mapped[str] = mapped_column(String(64))
    api_version: Mapped[str] = mapped_column(String(16), default=__version__)
    kind: Mapped[KindEvent] = mapped_column(Enum(KindEvent))
    kind_obj: Mapped[KindObject] = mapped_column(Enum(KindObject))
    detail: Mapped[str] = mapped_column(String(LENGTH_DESCRIPTION), nullable=True)

    def update(
        self,
        session: Session | None = None,
        _recurance: int = 0,
        *,
        api_origin: str | None = None,
        detail: str | None = None,
        uuid_user: str | None = None,
    ):
        "Update safe fields recursively. DOES NOT commit."

        session = session or self.get_session()
        if api_origin is not None:
            self.api_origin = api_origin
        if detail is not None:
            self.detail = detail
        if uuid_user is not None:
            self.uuid_user = uuid_user
        for child in self.children:
            child.update(
                session,
                _recurance + 1,
                api_origin=api_origin,
                detail=detail,
                uuid_user=uuid_user,
            )

    def undone(
        self,
        uuid_user: str,
        detail: str,
        api_origin: str,
        api_version: str = __version__,
        callback: Callable[["Event"], "Event"] | None = None,
    ) -> "Event":
        """Create the inverse event."""

        if self.uuid_undo:
            raise AttributeError("Cannot undo an event that has been undone.")

        common: Dict[str, Any] = dict(
            api_version=api_version,
            api_origin=api_origin,
            uuid_user=uuid_user,
            detail=detail,
        )

        children = [item.undone(**common, callback=callback) for item in self.children]
        event = self.__class__(
            uuid_undo=self.uuid,
            uuid_obj=self.uuid_obj,
            kind_obj=self.kind_obj,
            kind=KindEvent.restore,
            children=children,
            **common,
        )
        return event if callback is None else callback(event)

    def flattened(self) -> Generator["Event", None, None]:
        yield self
        for child in self.children:
            yield from child.flattened()

    @property
    def object_(self) -> "AnyModelBesidesEvent | None":
        session = self.get_session()
        t = Tables[self.kind_obj.value].value
        q = select(t).where(t.uuid == self.uuid_obj)
        res = session.execute(q).scalar()  # type: ignore
        if res is not None and res.__tablename__ == self.__tablename__:
            return None
        return res  # type: ignore

    @classmethod
    def cte_recursive(cls, uuid_event: str) -> CTE:
        rand = secrets.token_urlsafe(4)
        q = (
            select(
                Event,
                uuid_root := literal_column(f"'{uuid_event}'").label("uuid_root"),
                func.cast(Event.uuid, String(512)).label("path"),
                literal_column("0").label("level"),
            )
            .where(Event.uuid == uuid_event)
            .cte(f"find_children_{rand}", recursive=True)
        )

        roots_alias = q.alias(f"BB_{rand}")
        events_alias = Event.__table__.alias(f"AA_{rand}")

        p = select(
            events_alias,
            uuid_root,
            func.concat(roots_alias.c.path, ",", events_alias.c.uuid).label("path"),
            literal_column("level + 1").label("level"),
        ).where(
            events_alias.c.uuid_parent == roots_alias.c.uuid,
            func.find_in_set(events_alias.c.uuid, roots_alias.c.path) == 0,
        )
        q = q.union_all(p)
        return q

    @classmethod
    def q_select_recursive(
        cls,
        uuid_event: Set[str],
        kind_recurse: KindRecurse = KindRecurse.depth_first,
    ) -> CompoundSelect:
        def qq(uuid):
            q = select(cls.cte_recursive(uuid))
            match kind_recurse:
                case KindRecurse.depth_first:
                    q = q.order_by(literal_column("path"))
                case _:
                    pass
            q = q.order_by("timestamp")
            return q

        return union(*(qq(uuid) for uuid in uuid_event))

    @classmethod
    def q_select_search(
        cls,
        uuid_user: str,
        *,
        kind: str | None = None,
        kind_obj: str | None = None,
        uuid_obj: str | None = None,
    ) -> Select:
        q = select(cls.uuid).where(cls.uuid_user == uuid_user)
        if kind is not None:
            q = q.where(cls.kind == kind)
        if kind_obj is not None:
            q = q.where(cls.kind_obj == kind_obj)
        if uuid_obj is not None:
            q = q.where(cls.uuid_obj == uuid_obj)
        q = q.where(Event.uuid_parent.is_(None))
        return q

    def check_kind(
        self, kind: KindEvent | None = None, kind_obj: KindObject | None = None
    ) -> Self:
        detail = dict(uuid_event=self.uuid)
        fmt = "Expected event of kind `{}`."
        if kind is not None and self.kind != kind:
            msg = fmt.format(kind.name)
            detail.update(kind_event=self.kind, kind_expected=kind, msg=msg)
            raise HTTPException(400, detail=detail)
        if kind_obj is not None and self.kind_obj != kind_obj:
            msg = fmt.format(kind_obj.name)
            detail.update(
                kind_obj_event=self.kind_obj,
                kind_obj_expected=kind_obj,
                msg=fmt.format(kind_obj.name),
            )
            raise HTTPException(400, detail=detail)
        return self

    def check_not_undone(self):
        if self.uuid_undo is not None:
            msg = "Cannot undo event that has already been undone."
            detail = dict(uuid_event=self.uuid, uuid_undo=self.uuid_undo, detail=msg)
            raise HTTPException(400, detail=detail)
        return self

    def find_root(self, session: Session | None = None) -> "Event":
        if self.uuid_parent is None:
            return self

        session = session or self.get_session()
        next_ = session.execute(
            select(Event).where(Event.uuid == self.uuid_parent),
        ).scalar()
        if next_ is None:
            msg = "Could not find parent event. Inconcievable!"
            detail = dict(uuid_event=self.uuid, msg=msg)
            raise HTTPException(418, detail=detail)

        return next_


class AssocCollectionDocument(Base):
    __tablename__ = "_assocs_collections_documents"

    # NOTE: Since this object supports soft deletion (for the deletion grace
    #       period that will later be implemented) deleted is included.
    # deleted: Mapped[MappedColumnDeleted]
    id_document: Mapped[int] = mapped_column(
        ForeignKey("documents.id"),
        primary_key=True,
    )

    id_collection: Mapped[int] = mapped_column(
        ForeignKey("collections.id"),
        primary_key=True,
    )

    @property
    def uuid_document(self) -> str:
        session = self.get_session()
        res = session.execute(
            select(Document.uuid).where(Document.id == self.id_document)
        ).scalar()
        if res is None:
            raise ValueError("Inconcievable!")
        return res

    @property
    def uuid_collection(self) -> str:
        session = self.get_session()
        res = session.execute(
            select(Collection.uuid).where(Collection.id == self.id_collection)
        ).scalar()
        if res is None:
            raise ValueError("Inconcievable!")
        return res

    # @classmethod
    # def q_split(
    #     cls,
    #     source: "Collection | Document",
    #     uuid_targets: Set[str],
    #     *,
    #     select_parent_uuids: bool = False,
    # ) -> Tuple[Select, Select]:
    #     "Returns a select for assignment uuids."
    #
    #     # NOTE: These queries should also have joins such that warning are not
    #     #       raised by sqlalchemy.
    #     match source:
    #         case _ if not select_parent_uuids:
    #             q = source.q_select_assignment(
    #                 uuid_targets,
    #                 exclude_deleted=False,
    #             )
    #             s = literal_column("uuid")
    #         case Collection() as collection:
    #             q = collection.q_select_documents(
    #                 uuid_targets,
    #                 exclude_deleted=False,
    #             )
    #             s = literal_column("uuid_collection")
    #         case Document() as document:
    #             q = document.q_select_collections(
    #                 uuid_targets,
    #                 exclude_deleted=False,
    #             )
    #             s = literal_column("uuid_document")
    #
    #     return tuple(  # type: ignore
    #         select(s).select_from(q.where(Assignment.deleted == bool_()).subquery())
    #         for bool_ in (true, false)
    #     )
    #
    # @classmethod
    # def q_projection(cls, selectable, uuid_assignment: Set[str]) -> Select:
    #     return (
    #         select(selectable)
    #         .join(Assignment)
    #         .where(Assignment.uuid.in_(uuid_assignment))
    #     )
    #
    # @overload
    # @classmethod
    # def split(
    #     cls,
    #     session: Session,
    #     source: "Document",
    #     resolvable_target: "ResolvableMultiple[Collection]",
    #     *,
    #     select_parent_uuids: bool = False,
    # ) -> UUIDSplit: ...
    #
    # @overload
    # @classmethod
    # def split(
    #     cls,
    #     session: Session,
    #     source: "Collection",
    #     resolvable_target: "ResolvableMultiple[Document]",
    #     *,
    #     select_parent_uuids: bool = False,
    # ) -> UUIDSplit: ...
    #
    # @classmethod
    # def split(
    #     cls,
    #     session: Session,
    #     source: "Collection | Document",
    #     resolvable_target: "ResolvableMultiple[Collection] | ResolvableMultiple[Document]",
    #     *,
    #     select_parent_uuids: bool = False,
    # ) -> UUIDSplit:
    #
    #     match [source, resolvable_target]:
    #         case [Document() as document, _ as resolvable_collections]:
    #             uuid_collection = Collection.resolve_uuid(
    #                 session,
    #                 resolvable_collections,
    #             )
    #             qs = cls.q_split(
    #                 document,
    #                 uuid_collection,
    #                 select_parent_uuids=select_parent_uuids,
    #             )
    #         case [Collection() as collection, _ as resolvable_documents]:
    #             uuid_document = Document.resolve_uuid(
    #                 session,
    #                 resolvable_documents,
    #             )
    #             qs = cls.q_split(
    #                 collection,
    #                 uuid_document,
    #                 select_parent_uuids=select_parent_uuids,
    #             )
    #         case _:
    #             msg = f"Invalid source `{source}` of type `{type(source)}`. "
    #             msg += "Must be an instnce of `Collection` or `Document`."
    #             raise ValueError(msg)
    #
    #     # kind_target = cls.resolve_target_kind(source, resolvable_target)
    #     # is_doc = kind_target == ChildrenAssignment.documents
    #     # Target = Document if is_doc else Collection
    #     # uuid_target = Target.resolve_uuid(session, resolvable_target)  # type: ignore
    #     # qs = cls.q_split(uuid_document, collection)
    #
    #     res = tuple(set(session.execute(q).scalars()) for q in qs)
    #     return res  # type: ignore

    @classmethod
    def resolve_target_kind(
        cls,
        source: "Collection | Document",
        resolvable_target: "ResolvableMultiple[Collection] | ResolvableMultiple[Document]",
    ) -> ChildrenAssignment:
        match [source, resolvable_target]:
            case [Document()]:
                return ChildrenAssignment.collections
            case [Collection()]:
                return ChildrenAssignment.documents
            case _:
                msg = f"Invalid source `{source}` of type `{type(source)}`. "
                msg += "Must be an instnce of `Collection` or `Document`."
                raise ValueError(msg)


# NOTE: Should be able to be passed directly into `GrantSchema`.
class AssocUserDocument(Base):
    """Also known as :class:`Grant`. Determines user access to documents and
    facilitates invitations.

    See ``Granting Process`` in ``README.md``.

    :attr uuid: Global identifier.
    :attr deleted: Is this grant pending deletion? Grants pending deletion
        that have an active child grant will not be deleted to preserve
        integrity of the table, but will be set in a deleted state. The
        :class:`Event` corresponding to this deletion (generated by
        :class:`Delete`) will be handled by a cronjob or cue that will cleanup
        deleted grants that are not required for table integrity.
    :attr id_user: The user to whom the grant is.
    :attr id_document: The document for which the grant is.
    :attr level: The level provided by the grant, see :class:`Level`.
    :attr pending: Has this grant been accepting by the invited/requested
        party? The grant will not used to verify permissions when accessing
        documents unless pending is false.
    :attr pending_from: How was this grant created. For instance, this field
        should have ``PendingFrom.created`` when it from posting a new
        document, ``PendingFrom.grantee`` when a grantee requests access,
        and ``PendingFrom.granter`` when the grantee is invited.
    :attr uuid_parent: This allows the origin of any particular grant to be
        passed back. While a foreign key to ``User`` could be used this breaks
        joins:

        .. code:: STDERR

            sqlalchemy.exc.AmbiguousForeignKeysError: Can't determine join
            between 'users' and '_assocs_users_documents'; tables have more
            than one foreign key constraint relationship between them. Please
            specify the 'onclause' of this join explicitly.

        Further this lacks the ability to trace back the granting history.
    """

    __tablename__ = "_assocs_users_documents"

    # https://stackoverflow.com/questions/28843254/deleting-from-self-referential-inherited-objects-does-not-cascade-in-sqlalchemy
    uuid: Mapped[MappedColumnUUID] = mapped_column(primary_key=True)
    uuid_parent: Mapped[str] = mapped_column(
        ForeignKey("_assocs_users_documents.uuid", ondelete="CASCADE"),
        nullable=True,
    )
    children: Mapped[List["AssocUserDocument"]] = relationship(
        "AssocUserDocument",
        foreign_keys=uuid_parent,
        cascade="all, delete",
    )

    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"), key="a")
    id_document: Mapped[int] = mapped_column(ForeignKey("documents.id"), key="b")
    level: Mapped[Level] = mapped_column(Enum(Level))

    # Metadata
    pending: Mapped[bool] = mapped_column(default=True)
    pending_from: Mapped[PendingFrom] = mapped_column(Enum(PendingFrom))

    __table_args__ = (UniqueConstraint("a", "b", name="_grant_vector"),)

    # uuid: Mapped[MappedColumnUUID] = mapped_column(primary_key=True)
    # uuid_parent: Mapped[str] = mapped_column(
    #     ForeignKey("events.uuid"),
    #     nullable=True,
    # )

    @property
    def uuid_document(self) -> str:
        session = self.get_session()
        res = session.execute(
            select(Document.uuid).where(Document.id == self.id_document)
        ).scalar()
        if res is None:
            raise ValueError("Inconcievable!")
        return res

    @property
    def uuid_user(self) -> str:
        session = self.get_session()
        res = session.execute(select(User.uuid).where(User.id == self.id_user)).scalar()
        if res is None:
            raise ValueError("Inconcievable!")
        return res

    @property
    def uuid_user_granter(self) -> str:
        session = self.get_session()
        res = session.execute(
            select(User.uuid).where(User.id == self.id_user_granter)
        ).scalar()
        if res is None:
            raise ValueError("Inconcievable!")
        return res

    @classmethod
    def resolve_from_target(
        cls, session: Session, source: "User | Document", uuid_target: Set[str]
    ) -> Tuple[Self, ...]:
        q = select(cls).join(User).join(Document)
        match source:
            case User(uuid=uuid_user):
                conds = (User.uuid == uuid_user, Document.uuid.in_(uuid_target))
            case Document(uuid=uuid_doc):
                conds = (Document.uuid == uuid_doc, User.uuid.in_(uuid_target))
            case _:
                raise HTTPException(500, detail="Cannot resolve.")

        q = q.where(*conds)
        util.sql(session, q)
        return tuple(session.execute(q).scalars())

    # ----------------------------------------------------------------------- #
    # Eventually to merged with the corresponding methods of `Assignment`

    @classmethod
    def q_split(
        cls,
        source: "User | Document",
        target_uuids: Set[str],
        *,
        select_parent_uuids: bool = False,
    ) -> Tuple[Select, Select]:
        "Returns a select for assignment uuids."

        # NOTE: These queries should also have joins such that warning are not
        #       raised by sqlalchemy.
        match source:
            case _ if not select_parent_uuids:
                q = source.q_select_grants(target_uuids, exclude_deleted=False)
                s = literal_column("uuid")
            case User() as user:
                q = user.q_select_documents(target_uuids, exclude_deleted=False)
                s = literal_column("uuid_user")
            case Document() as document:
                q = document.q_select_users(target_uuids, exclude_deleted=False)
                s = literal_column("uuid_document")

        return tuple(  # type: ignore
            select(s).select_from(q.where(Grant.deleted == bool_()).subquery())
            for bool_ in (true, false)
        )

    # @overload
    # @classmethod
    # def split(
    #     cls,
    #     session: Session,
    #     source: "Document",
    #     resolvable_target: "ResolvableMultiple[User]",
    #     *,
    #     select_parent_uuids: bool = False,
    # ) -> UUIDSplit: ...
    #
    # @overload
    # @classmethod
    # def split(
    #     cls,
    #     session: Session,
    #     source: "User",
    #     resolvable_target: "ResolvableMultiple[Document]",
    #     *,
    #     select_parent_uuids: bool = False,
    # ) -> UUIDSplit: ...

    @classmethod
    def split(
        cls,
        session: Session,
        source: "User | Document",
        uuid_target: Set[str],
        *,
        select_parent_uuids: bool = False,
    ) -> UUIDSplit:

        qs = cls.q_split(
            source,
            uuid_target,
            select_parent_uuids=select_parent_uuids,
        )
        res = tuple(set(session.execute(q).scalars()) for q in qs)
        return res  # type: ignore


class User(SearchableTableMixins, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )
    name: Mapped[str] = mapped_column(String(LENGTH_NAME), unique=True)
    description: Mapped[str] = mapped_column(String(LENGTH_DESCRIPTION))
    url_image: Mapped[str] = mapped_column(String(LENGTH_URL), nullable=True)
    url: Mapped[str] = mapped_column(String(LENGTH_URL), nullable=True)

    # documents: Mapped[Dict[str, List[str]]] = relationship(Documents)

    # NOTE: This should correspond to `user`. Is all of the collection objects
    #       labeled by their names.
    collections: Mapped[Dict[str, "Collection"]] = relationship(
        collection_class=attribute_keyed_dict("uuid"),
        cascade="all, delete",
        back_populates="user",
        primaryjoin="and_(User.id==Collection.id_user, Collection.deleted == false())",
    )

    edits: Mapped[List["Edit"]] = relationship(
        # cascade="all, delete",
        back_populates="user",
        primaryjoin="User.id==Edit.id_user",
    )

    documents: Mapped[Dict[str, "Document"]] = relationship(
        collection_class=attribute_keyed_dict("uuid"),
        secondary=AssocUserDocument.__table__,
        back_populates="users",
        primaryjoin="and_(User.id==AssocUserDocument.id_user, Document.deleted == false())",
        secondaryjoin="AssocUserDocument.id_document==Document.id",
    )

    events: Mapped[Event] = relationship(back_populates="user", cascade="all, delete")

    # ----------------------------------------------------------------------- #
    # Queries

    def q_conds_grants(
        self,
        document_uuids: None | Set[str] = None,
        level: Level | None = None,
        exclude_deleted: bool = True,
        pending: bool = False,
    ) -> ColumnElement[bool]:
        cond = AssocUserDocument.id_user == self.id
        if exclude_deleted:
            cond = and_(
                Document.deleted == false(),
                AssocUserDocument.deleted == false(),
                cond,
            )

        if document_uuids is not None:
            cond = and_(
                cond,
                AssocUserDocument.id_document.in_(
                    select(Document.id).where(Document.uuid.in_(document_uuids))
                ),
            )
        if level is not None:
            cond = and_(cond, Grant.level >= level.value)

        cond = and_(cond, Grant.pending == (true() if pending else false()))

        return cond

    def q_select_grants(
        self,
        document_uuids: None | Set[str] = None,
        level: Level | None = None,
        exclude_deleted: bool = True,
        pending: bool = False,
    ) -> Select:
        # NOTE: Attempting to make roughly the following query:
        #
        #       .. code::
        #
        #          SELECT users.uuid,
        #                 documents.uuid,
        #                 _assocs_user_documents.level
        #          FROM users
        #          JOIN _assocs_user_documents
        #               ON _assocs_user_documents.id_user=users.id
        #          JOIN documents
        #               ON _assocs_user_documents.id_document = documents.id;
        q = select(Grant).select_from(User).join(AssocUserDocument).join(Document)
        conds = self.q_conds_grants(
            document_uuids, level, exclude_deleted=exclude_deleted, pending=pending
        )
        q = q.where(conds)
        return q

    def q_select_documents(
        self,
        document_uuids: Set[str] | None = None,
        level: Level | None = None,
        exclude_deleted: bool = True,
    ) -> Select:
        """Dual to :meth:`q_select_user_uuids`."""

        return (
            select(Document)
            .join(AssocUserDocument)
            .where(
                self.q_conds_grants(document_uuids, level, exclude_deleted),
            )
        )

    def q_select_documents_assignable(self, document_uuids: Set[str] | None = None):
        """Get documents that can be assigned to user collections"""

        return union(
            self.q_select_documents(document_uuids),
            Document.q_select_public(document_uuids),
        )

    def q_select_documents_exclusive(self, document_uuids: Set[str] | None = None):
        level = Level.own
        q = (
            select(Document.id, func.count(Document.id).label("owner_count"))
            .select_from(self.q_select_documents(document_uuids, level))
            .group_by(Document.id)
        )
        q = (
            select(Document.id)
            .select_from(q)
            .where(
                literal_column("owner_count") == 1,
            )
        )
        q = select(Document).where(Document.id.in_(q))
        return q

    @classmethod
    def q_select_for_user(
        cls,
        user_uuid: str | None,
        uuids: Set[str] | None,
        exclude_deleted: bool = True,
    ) -> Select:
        return cls.q_select_public(uuids, exclude_deleted)

    # ----------------------------------------------------------------------- #
    # Chainables for endpoints.

    # NOTE: Chainable methods should be prefixed with `check_`.
    def check_can_access_collection(self, collection: "Collection") -> Self:
        if not collection.public and collection.id_user != self.id:
            raise HTTPException(
                403,
                detail=dict(
                    msg="Cannot access private collection.",
                    uuid_user=self.uuid,
                    uuid_collection=collection.uuid,
                ),
            )
        return self

    def check_can_access_document(
        self,
        document: "Document",
        level: Level,
        *,
        grants: Dict[str, "Grant"] | None = None,
        grants_index: Literal["uuid_document", "uuid_user"] = "uuid_document",
    ) -> Self:
        # If the document is public and the level is view, then don't check.
        if document.public and level == Level.view:
            return self

        session = self.get_session()

        # Deleted and insufficient should be included for better feedback.
        q = self.q_select_grants({document.uuid}, exclude_deleted=False)
        q_uuid_grant = select(literal_column("uuid")).select_from(q.subquery())
        q_grant = select(Grant).where(Grant.uuid.in_(q_uuid_grant))
        res = session.execute(q_grant).scalars()
        assocs: List[AssocUserDocument] = list(res)

        detail = dict(uuid_user=self.uuid, uuid_document=document.uuid)
        match assocs:
            case []:
                detail.update(
                    msg="Grant does not exist.",
                    level_grant_required=level.name,
                )
                raise HTTPException(403, detail=detail)
            case [
                Grant(deleted=False, pending=True, pending_from=pending_from) as grant
            ]:
                match pending_from:
                    case PendingFrom.grantee:
                        msg = "Grant is pending. Document owner must approve "
                        msg += "request for access."
                    case PendingFrom.granter:
                        msg = "Grant is pending. User must accept invitation."
                    case _:
                        msg = "Grant is pending while in `pending_from` is "
                        msg += "`created`."
                        detail.update(msg=msg)
                        raise HTTPException(500, detail=detail)

                detail.update(msg=msg)
                raise HTTPException(403, detail=detail)
            case [Grant(deleted=False) as grant]:
                if grant.level.value < level.value:
                    detail.update(
                        msg="Grant insufficient.",
                        uuid_grant=grant.uuid,
                        level_grant=grant.level.name,
                        level_grant_required=level.name,
                    )
                    raise HTTPException(403, detail=detail)
                if grants is not None:
                    grants[getattr(grant, grants_index)] = grant
                return self
            case [Grant(deleted=True) as grant]:
                detail.update(msg="Grant is deleted.", uuid_grant=grant.uuid)
                raise HTTPException(410, detail=detail)
            case _:
                # Server is a teapot because this is unlikely to ever happen.
                detail.update(msg="There should only be one grant.")
                raise HTTPException(418, detail=detail)

    def check_sole_owner_document(self, document: "Document") -> Self: ...

    def check_can_access_event(self, event: Event, status_code: int = 403) -> Self:
        if self.uuid != event.uuid_user:
            detail = dict(uuid_event=event.uuid, uuid_user=self.uuid)
            detail.update(msg="User cannot access event.")
            raise HTTPException(status_code, detail=detail)

        return self


class Collection(SearchableTableMixins, Base):
    __tablename__ = "collections"

    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(LENGTH_NAME))
    description: Mapped[str] = mapped_column(
        String(LENGTH_DESCRIPTION),
        nullable=True,
    )

    # NOTE: This corresponds to `User.collections`.
    user: Mapped[User] = relationship(
        primaryjoin="User.id==Collection.id_user",
        back_populates="collections",
    )

    # NOTE: Deletion is included here since this used to read collection
    #       documents.
    documents: Mapped[Dict[str, "Document"]] = relationship(
        collection_class=attribute_keyed_dict("name"),
        secondary=AssocCollectionDocument.__table__,
        back_populates="collections",
        primaryjoin="and_(Collection.id==AssocCollectionDocument.id_collection, AssocCollectionDocument.deleted == false())",
        secondaryjoin="and_(Document.deleted == false(), Document.id==AssocCollectionDocument.id_document)",
    )

    def q_conds_assignment(
        self,
        document_uuids: Set[str] | None = None,
        exclude_deleted: bool = True,
    ) -> ColumnElement[bool]:
        # NOTE: To add the conditions for document select (like level) use
        #       `q_conds_assoc`.
        cond = and_(AssocCollectionDocument.id_collection == self.id)
        if exclude_deleted:
            cond = and_(cond, AssocCollectionDocument.deleted == false())
        if document_uuids is not None:
            document_ids = Document.q_select_ids(document_uuids)
            cond = and_(cond, AssocCollectionDocument.id_document.in_(document_ids))
        # cond = and_(cond, self.q_conds(document_uuids, exclude_deleted))

        return cond

    def q_select_assignment(
        self,
        document_uuids: Set[str] | None = None,
        exclude_deleted: bool = True,
    ) -> Select:
        q = (
            select(
                AssocCollectionDocument,
                Document.uuid.label("uuid_document"),
                Collection.uuid.label("uuid_collection"),
            )
            .join(Collection)
            .join(Document)
        )
        q = q.where(self.q_conds_assignment(document_uuids, exclude_deleted))
        return q

    def q_select_documents(
        self,
        document_uuids: Set[str] | None = None,
        exclude_deleted: bool = True,
    ) -> Select:
        q = (
            select(Document)
            .join(AssocCollectionDocument)
            .where(self.q_conds_assignment(document_uuids, exclude_deleted))
        )
        return q

    @classmethod
    def q_select_for_user(
        cls,
        user_uuid: str,
        uuids: Set[str] | None,
        exclude_deleted: bool = True,
    ) -> Select:
        return (
            select(Collection)
            .join(User)
            .where(User.uuid == user_uuid)
            .where(cls.q_conds(uuids, exclude_deleted))
        )


class Document(SearchableTableMixins, Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(LENGTH_NAME))
    description: Mapped[str] = mapped_column(String(LENGTH_DESCRIPTION))
    content: Mapped[str] = mapped_column(mysql.BLOB(LENGTH_CONTENT))
    format: Mapped[str] = mapped_column(String(LENGTH_FORMAT))

    edits: Mapped[List["Edit"]] = relationship(
        cascade="all, delete",
        back_populates="document",
        primaryjoin="Document.id==Edit.id_document",
    )
    users: Mapped[Dict[str, User]] = relationship(
        collection_class=attribute_keyed_dict("name"),
        secondary=AssocUserDocument.__table__,
        back_populates="documents",
        secondaryjoin="User.id==AssocUserDocument.id_user",
        primaryjoin="AssocUserDocument.id_document==Document.id",
    )
    collections: Mapped[Dict[str, Collection]] = relationship(
        collection_class=attribute_keyed_dict("name"),
        secondary=AssocCollectionDocument.__table__,
        back_populates="documents",
    )

    # ----------------------------------------------------------------------- #
    # Queries

    def q_conds_grants(
        self,
        user_uuids: Set[str] | None = None,
        level: Level | None = None,
        exclude_deleted: bool = True,
        pending: bool = False,
    ) -> ColumnElement[bool]:
        cond = AssocUserDocument.id_document == self.id
        if exclude_deleted:
            cond = and_(
                cond,
                AssocUserDocument.deleted == false(),
                User.deleted == false(),
            )
        if user_uuids is not None:
            cond = and_(
                cond,
                AssocUserDocument.id_user.in_(
                    select(User.id).where(User.uuid.in_(user_uuids))
                ),
            )
        if level is not None:
            cond = and_(cond, AssocUserDocument.level >= level)
        cond = and_(cond, Grant.pending == (true() if pending else false()))
        return cond

    def q_select_grants(
        self,
        user_uuids: Set[str] | None = None,
        level: Level | None = None,
        exclude_deleted: bool = True,
        pending: bool = False,
    ) -> Select:
        """Query to find grants (AssocUserDocument) for this document.

        To find grants for a user, see the same named method on :class:`User`.

        :param user_uuids: The uuids of the users to select for.
        :param level: The minimal level to select joined entries from.
        """
        conds = self.q_conds_grants(
            user_uuids=user_uuids,
            level=level,
            exclude_deleted=exclude_deleted,
            pending=pending,
        )
        return select(Grant).join(Document).join(User).where(conds)

    def q_select_users(
        self,
        user_uuids: Set[str] | None = None,
        level: Level | None = None,
    ) -> Select:
        """Select user uuids for this document.

        For parameter descriptions, see :meth:`q_select_grants`.
        """
        q = (
            select(User)
            .join(AssocUserDocument)
            .where(self.q_conds_grants(user_uuids=user_uuids, level=level))
        )
        return q

    def q_conds_assignment(
        self,
        collection_uuids: Set[str] | None = None,
        exclude_deleted: bool = True,
    ) -> ColumnElement[bool]:
        # NOTE: To add the conditions for document select (like level) use
        #       `q_conds_assoc`.
        cond = and_(AssocCollectionDocument.id_document == self.id)
        if exclude_deleted:
            cond = and_(
                cond,
                AssocCollectionDocument.deleted == false(),
            )
        if collection_uuids is not None:
            collection_ids = Collection.q_select_ids(collection_uuids)
            cond = and_(cond, AssocCollectionDocument.id_collection.in_(collection_ids))

        return cond

    def q_select_assignment(
        self,
        collection_uuids: Set[str] | None = None,
        exclude_deleted: bool = True,
    ) -> Select:
        q = (
            select(
                AssocCollectionDocument,
                Document.uuid.label("uuid_document"),
                Collection.uuid.label("uuid_collection"),
            )
            .join(Document)
            .join(Collection)
        )
        q = q.where(self.q_conds_assignment(collection_uuids, exclude_deleted))
        return q

    def q_select_collections(
        self,
        collection_uuids: Set[str] | None = None,
        exclude_deleted: bool = True,
    ) -> Select:
        q = (
            select(Collection)
            .join(Assignment)
            .where(self.q_conds_assignment(collection_uuids, exclude_deleted))
        )
        return q

    @classmethod
    def q_select_for_user(
        cls,
        user_uuid: str,
        uuids: Set[str] | None,
        exclude_deleted: bool = True,
    ) -> Select:
        return (
            select(Document)
            .join(AssocUserDocument)
            .join(User)
            .where(User.uuid == user_uuid)
            .where(cls.q_conds(uuids, exclude_deleted))
        )


class Edit(PrimaryTableMixins, Base):
    __tablename__ = "edits"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    id_document: Mapped[int] = mapped_column(ForeignKey("documents.id"))
    content: Mapped[int] = mapped_column(mysql.BLOB(LENGTH_CONTENT))
    message: Mapped[str] = mapped_column(String(LENGTH_MESSAGE), nullable=True)

    user: Mapped[User] = relationship(
        primaryjoin="User.id==Edit.id_user",
        back_populates="edits",
    )

    document: Mapped[Document] = relationship(
        primaryjoin="Document.id==Edit.id_document",
        back_populates="edits",
    )


# --------------------------------------------------------------------------- #
# After the matter constants and types.


class Tables(enum.Enum):
    assignments = AssocCollectionDocument
    grants = AssocUserDocument
    events = Event
    users = User
    collections = Collection
    documents = Document
    edits = Edit

    _assocs_user_documents = AssocUserDocument
    _assocs_collections_documents = AssocCollectionDocument


Assignment = AssocCollectionDocument
Grant = AssocUserDocument
AnyModelBesidesEvent = (
    AssocUserDocument | AssocCollectionDocument | User | Collection | Document | Edit
)
AnyModel = Event | AnyModelBesidesEvent

# Resolvables

T_Resolvable = TypeVar(
    "T_Resolvable",
    AssocUserDocument,
    AssocCollectionDocument,
    User,
    Collection,
    Document,
    Edit,
)

ResolvableSingular: TypeAlias = T_Resolvable | str
ResolvableMultiple: TypeAlias = Tuple[T_Resolvable, ...] | Set[str]
Resolvable: TypeAlias = T_Resolvable | str | Tuple[T_Resolvable, ...] | Set[str]

ResolvableSourceAssignment: TypeAlias = (
    ResolvableSingular[Collection] | ResolvableSingular[Document]
)
ResolvableTargetAssignment: TypeAlias = (
    ResolvableMultiple[Document] | ResolvableMultiple[Collection]
)
ResolvableSourceGrant: TypeAlias = (
    ResolvableSingular[User] | ResolvableSingular[Collection]
)
ResolvableTargetGrant: TypeAlias = (
    ResolvableMultiple[User] | ResolvableMultiple[Collection]
)


# Resolved result.
ResolvedRaw = Tuple[T_Resolvable] | Resolvable
ResolvedRawUser = ResolvedRaw[User]
ResolvedRawCollection = ResolvedRaw[Collection]
ResolvedRawDocument = ResolvedRaw[Document]
ResolvedRawEdit = ResolvedRaw[Edit]

ResolvedRawAssignmentDocument = Tuple[Document, Tuple[Collection, ...]]
ResolvedRawAssignmentCollection = Tuple[Collection, Tuple[Document, ...]]
ResolvedRawAssignment = ResolvedRawAssignmentDocument | ResolvedRawAssignmentCollection

ResolvedRawGrantUser = Tuple[User, Tuple[Document, ...]]
ResolvedRawGrantDocument = Tuple[Document, Tuple[User, ...]]
ResolvedRawGrant = ResolvedRawGrantUser | ResolvedRawGrantDocument

ResolvedRawAny = (
    ResolvedRawCollection
    | ResolvedRawUser
    | ResolvedRawDocument
    | ResolvedRawEdit
    | ResolvedRawAssignment
    | ResolvedRawGrant
)


def uuids(vs: Resolvable[T_Resolvable]) -> Set[str]:
    match vs:
        case tuple():
            return {vv.uuid for vv in vs}
        case set():
            return vs
        case str():
            return {vs}
        case _ as item:
            return {item.uuid}


__all__ = (
    "Base",
    "User",
    "Collection",
    "AssocCollectionDocument",
    "AssocUserDocument",
    "Document",
    "Edit",
    "Tables",
    "KindEvent",
    "KindObject",
    "Level",
    "LevelStr",
    "KindObject",
    "ChildrenUser",
    "ChildrenCollection",
    "ChildrenDocument",
)
