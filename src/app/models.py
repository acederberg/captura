# import abc
import enum
import secrets
from datetime import datetime
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Collection,
    Dict,
    Generator,
    List,
    Literal,
    Self,
    Set,
    Tuple,
    TypeAlias,
    TypeVar,
    overload,
)

from fastapi import HTTPException
from sqlalchemy import (
    CTE,
    BooleanClauseList,
    Column,
    ColumnElement,
    CompoundSelect,
    Enum,
    ForeignKey,
    Select,
    String,
    UniqueConstraint,
    and_,
    func,
    literal_column,
    select,
    true,
    union,
)
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import (
    DeclarativeBase,
    InstrumentedAttribute,
    Mapped,
    Session,
    mapped_column,
    object_session,
    relationship,
)
from sqlalchemy.orm.mapped_collection import attribute_keyed_dict
from sqlalchemy.sql import false

from app import __version__, fields, util
from app.err import (
    ErrAccessDocumentGrantBase,
    ErrAccessDocumentGrantInsufficient,
    ErrAccessDocumentPending,
    ErrAccessEvent,
    ErrEventGeneral,
    ErrEventKind,
    ErrEventUndone,
    ErrObjMinSchema,
)
from app.fields import (
    LENGTH_CONTENT,
    LENGTH_DESCRIPTION,
    LENGTH_FORMAT,
    LENGTH_MESSAGE,
    LENGTH_NAME,
    LENGTH_TITLE,
    LENGTH_URL,
    ChildrenAssignment,
    ChildrenCollection,
    ChildrenDocument,
    ChildrenGrant,
    ChildrenUser,
    Format,
    KindEvent,
    KindObject,
    KindRecurse,
    Level,
    LevelHTTP,
    LevelStr,
    PendingFrom,
    Plural,
    ResolvableLevel,
    Singular,
)

# =========================================================================== #
# CONSTANTS, ENUMS, ETC.
#
# NOTE: These enums will be used throughout the program and a should be used
#       to create the types needed by fastapi and typer.
#

UUIDSplit = Tuple[Set[str], Set[str]]
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
    def q_events(self):
        return (
            select(Event).where(Event.uuid_obj == self.uuid).order_by(Event.timestamp)
        )

    @classmethod
    def if_exists(
        cls,
        session: Session,
        uuid: str,
        # status: int = 404, msg=None
    ) -> Self:

        m = session.execute(select(cls).where(cls.uuid == uuid)).scalar()
        if m is None:
            err = ErrObjMinSchema.httpexception(
                "_msg_dne", 404, uuid_obj=uuid, kind_obj=KindObject(cls.__tablename__)
            )
            raise err
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
                msg = f"Cannot resolve `{bad}` (of type `{bad}`) for mapped "
                msg += f"class `{cls.__name__}`."
                raise ValueError(msg)

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
            raise ValueError(str(detail))
        return session

    def check_not_deleted(
        self,
        # status_code: int = 410,
        # deleted: bool = True,
    ) -> Self:
        if self.deleted:
            err = ErrObjMinSchema.httpexception(
                "_msg_deleted",
                410,
                uuid_obj=self.uuid,
                kind_obj=KindObject(self.__tablename__),
            )
            raise err
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
        uuids: Set[str] | str | None = None,
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

    detail_document_editted: ClassVar[str] = "Document editted."

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

    uuid_obj: Mapped[MappedColumnUUID | None]
    api_origin: Mapped[str] = mapped_column(String(64))
    api_version: Mapped[str] = mapped_column(String(16), default=__version__)
    kind: Mapped[KindEvent] = mapped_column(Enum(KindEvent))
    kind_obj: Mapped[KindObject] = mapped_column(Enum(KindObject))
    detail: Mapped[str | None] = mapped_column(
        String(fields.LENGTH_DESCRIPTION), nullable=True
    )

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

    def flattened(self) -> Generator["Event", None, None]:
        yield self
        yield from (
            child_child for child in self.children for child_child in child.flattened()
        )

    @property
    def object_(self) -> "AnyModel | None":
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
    def q_conds(
        cls,
        uuid_user: str | None = None,
        uuid_event: Set[str] | None = None,
        kind: str | None = None,
        kind_obj: str | None = None,
        uuid_obj: str | None = None,
        before: int | None = None,
        after: int | None = None,
    ) -> ...:

        conds = []
        if uuid_user is not None:
            conds.append(cls.uuid_user == uuid_user)
        if uuid_event is not None:
            conds.append(cls.uuid.in_(uuid_event))
        if kind is not None:
            conds.append(cls.kind == kind)
        if kind_obj is not None:
            conds.append(cls.kind_obj == kind_obj)
        if uuid_obj is not None:
            conds.append(cls.uuid_obj == uuid_obj)
        if before is not None:
            conds.append(cls.timestamp < before)
        if after is not None:
            conds.append(cls.timestamp > after)
        return and_(*conds)

    @classmethod
    def q_select_search(
        cls,
        # From `EventSearchSchema`.
        uuid_user: str | None = None,
        uuid_event: Set[str] | None = None,
        kind: str | None = None,
        kind_obj: str | None = None,
        uuid_obj: str | None = None,
        after: int | None = None,
        before: int | None = None,
        limit: int | None = None,
    ) -> Select:
        q = (
            select(cls)
            .where(
                cls.q_conds(
                    uuid_user=uuid_user,
                    uuid_event=uuid_event,
                    kind=kind,
                    kind_obj=kind_obj,
                    uuid_obj=uuid_obj,
                    before=before,
                    after=after,
                )
            )
            .order_by(cls.timestamp)
        )
        if limit:
            q = q.limit(limit)

        return q

    def check_kind(
        self, kind: KindEvent | None = None, kind_obj: KindObject | None = None
    ) -> Self:
        if kind is not None and self.kind != kind:
            raise ErrEventKind.httpexception(
                "_msg_kind_obj",
                400,
                kind_event=self.kind,
                kind_expected=kind,
                uuid_event=self.uuid,
            )
        if kind_obj is not None and self.kind_obj != kind_obj:
            raise ErrEventKind.httpexception(
                "_msg_kind_event",
                400,
                kind_obj_event=self.kind_obj,
                kind_obj_expected=kind_obj,
                uuid_event=self.uuid,
            )
        return self

    def check_not_undone(self):
        if self.uuid_undo is not None:
            err = ErrEventUndone.httpexception(
                "_msg_undone",
                400,
                uuid_event=self.uuid,
                uuid_event_undo=self.uuid_undo,
            )
            raise err
        return self

    def find_root(self, session: Session | None = None) -> "Event":
        if self.uuid_parent is None:
            return self

        session = session or self.get_session()
        next_ = session.execute(
            select(Event).where(Event.uuid == self.uuid_parent),
        ).scalar()
        if next_ is None:
            raise ErrEventGeneral.httpexception(
                "_msg_undone",
                400,
                uuid_event=self.uuid,
            )

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
            case bad:
                raise ValueError(f"Invalid input `{bad}`.")

        q = q.where(*conds)
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


class User(SearchableTableMixins, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )
    name: Mapped[str] = mapped_column(String(fields.LENGTH_NAME), unique=True)
    description: Mapped[str] = mapped_column(String(fields.LENGTH_DESCRIPTION))
    url_image: Mapped[str] = mapped_column(String(fields.LENGTH_URL), nullable=True)
    url: Mapped[str] = mapped_column(String(fields.LENGTH_URL), nullable=True)
    admin: Mapped[bool] = mapped_column(default=False)

    # NOTE: This will be used to implement use by invitation for users. More or
    #       less, for a user to register they will need to first be given their
    #       activation code.
    _prototype_activation_invitation_code: Mapped[str] = mapped_column(
        String(36),
        unique=True,
        nullable=True,
        # default=lambda: str(uuid4()),
    )
    _prototype_activation_invitation_email: Mapped[str] = mapped_column(
        String(128), nullable=True
    )
    _prototype_activation_pending_approval: Mapped[bool] = mapped_column(
        nullable=True,
    )

    @property
    def pending_approval(self):
        return self._prototype_activation_pending_approval

    # NOTE: This should correspond to `user`. Is all of the collection objects
    #       labeled by their names.
    collections: Mapped[List["Collection"]] = relationship(
        # collection_class=attribute_keyed_dict("uuid"),
        cascade="all, delete",
        back_populates="user",
        primaryjoin="and_(User.id==Collection.id_user, Collection.deleted == false())",
    )

    edits: Mapped[List["Edit"]] = relationship(
        # cascade="all, delete",
        back_populates="user",
        primaryjoin="User.id==Edit.id_user",
    )

    documents: Mapped[List["Document"]] = relationship(
        # collection_class=attribute_keyed_dict("uuid"),
        secondary=AssocUserDocument.__table__,
        back_populates="users",
        primaryjoin="and_(User.id==AssocUserDocument.id_user, Document.deleted == false())",
        secondaryjoin="AssocUserDocument.id_document==Document.id",
    )

    # DOES NOT INCLUDE WHERE user is subject
    events: Mapped[Event] = relationship(back_populates="user", cascade="all, delete")

    # ----------------------------------------------------------------------- #
    # Queries

    @classmethod
    def _q_prototype_activation_pending_approval(
        cls,
        invitation_uuid: Set[str] | None = None,
        invitation_email: Set[str] | None = None,
        invitation_code: Set[str] | None = None,
    ) -> Select:
        q = select(cls).where(
            cls.deleted == true(), cls._prototype_activation_pending_approval == true()
        )
        if invitation_uuid is not None:
            q = q.where(cls.uuid.in_(invitation_uuid))

        if invitation_code is not None:
            q = q.where(cls._prototype_activation_invitation_code.in_(invitation_code))

        if invitation_email is not None:
            q = q.where(
                cls._prototype_activation_invitation_email.in_(invitation_email)
            )

        return q

    def q_conds_grants(
        self,
        document_uuids: None | Set[str] = None,
        level: ResolvableLevel | None = None,
        exclude_deleted: bool = True,
        pending: bool | None = None,
        pending_from: PendingFrom | None = None,
        exclude_pending: bool = True,
    ) -> ColumnElement[bool]:
        cond = AssocUserDocument.id_user == self.id
        if exclude_deleted:
            cond = and_(
                Document.deleted == false(),
                AssocUserDocument.deleted == false(),
                cond,
            )

        if document_uuids is not None:
            q_ids = select(Document.id)
            q_ids = q_ids.where(Document.uuid.in_(document_uuids))
            cond = and_(cond, AssocUserDocument.id_document.in_(q_ids))

        if level is not None:
            level = Level.resolve(level)
            cond = and_(cond, Grant.level >= level.value)

        match (pending, exclude_pending):
            case (True, True):
                msg = "`pending` and `exclude_pending` cannot both be `True`."
                raise ValueError(msg)
            case (bool() as pending, False):
                cond = and_(cond, Grant.pending == (true() if pending else false()))
            case (None | False, True):
                cond = and_(cond, Grant.pending == false())
            case (None, False):
                pass
            case bad:
                raise ValueError(f"Cannot handle case `{bad}`.")

        if pending_from is not None:
            cond = and_(cond, Grant.pending_from == pending_from)

        return cond

    def q_select_grants(
        self,
        document_uuids: None | Set[str] = None,
        level: ResolvableLevel | None = None,
        exclude_deleted: bool = True,
        pending: bool | None = None,
        exclude_pending: bool = True,
        pending_from: PendingFrom | None = None,
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
            document_uuids,
            level,
            exclude_deleted=exclude_deleted,
            pending=pending,
            exclude_pending=exclude_pending,
            pending_from=pending_from,
        )
        q = q.where(conds)
        return q

    def q_select_documents(
        self,
        document_uuids: Set[str] | None = None,
        level: ResolvableLevel | None = None,
        exclude_deleted: bool = True,
        exclude_pending: bool = True,
        pending: bool = False,
        pending_from: PendingFrom | None = None,
    ) -> Select:
        """Dual to :meth:`q_select_user_uuids`."""

        return (
            select(Document)
            .join(AssocUserDocument)
            .where(
                self.q_conds_grants(
                    document_uuids,
                    level,
                    exclude_deleted,
                    exclude_pending=exclude_pending,
                    pending=pending,
                    pending_from=pending_from,
                ),
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
        _: str | None,
        uuids: Set[str] | None,
        exclude_deleted: bool = True,
    ) -> Select:
        # NOTE: This should get collaborators, etc. in the future.
        return cls.q_select_public(uuids, exclude_deleted)

    def q_conds_collections(
        self,
        uuid_collection: Set[str] | None = None,
        exclude_deleted: bool = True,
    ) -> ...:
        conds = and_(Collection.id_user == User.id)
        if uuid_collection is not None:
            conds = and_(conds, Collection.uuid.in_(uuid_collection))
        if exclude_deleted:
            conds = and_(conds, Collection.deleted == false())
        return conds

    def q_collections(
        self,
        uuid_collection: Set[str] | None = None,
        exclude_deleted: bool = True,
    ) -> Select:
        conds = self.q_conds_collections(
            uuid_collection=uuid_collection,
            exclude_deleted=exclude_deleted,
        )
        return select(Collection).where(conds)

    # ----------------------------------------------------------------------- #
    # Chainables for endpoints.

    # NOTE: Chainable methods should be prefixed with `check_`.
    # def check_can_access_collection(self, collection: "Collection") -> Self:
    # return self

    def check_can_access_document(
        self,
        document: "Document",
        level: ResolvableLevel,
        *,
        grants: Dict[str, "Grant"] | None = None,
        grants_index: Literal["uuid_document", "uuid_user"] = "uuid_document",
        pending: bool = False,
        exclude_deleted: bool = True,
        validate: bool = True,
    ) -> Self:
        "Less horrific."

        def do_grant(grant):
            if grants is not None and grant is not None:
                grants[getattr(grant, grants_index)] = grant

        # NOTE: If the document is public and the level is view, then don't check.
        #       These lines can cause an issue where grants are not correctly
        #       added,
        # NOTE: Deleted, pending, insufficient should be included for better
        #       feedback. Do not exclude when adding.
        level, session = Level.resolve(level), self.get_session()
        q = self.q_select_grants(
            {document.uuid}, exclude_deleted=False, exclude_pending=False
        )

        res: Grant | None = session.execute(q).scalar()  # type: ignore
        detail: Dict[str, Any] = dict(
            uuid_user=self.uuid,
            uuid_document=document.uuid,
            level_grant_required=level,
        )

        if not validate:
            do_grant(res)
            return self

        match res:
            case None:
                raise ErrAccessDocumentGrantBase.httpexception(
                    "_msg_dne",
                    403,
                    level=level.name,
                    **detail,
                )
            case Grant(
                deleted=False, pending=True, pending_from=pending_from
            ) as grant if not pending:
                status, msg = 403, "_msg_grant_pending"
                if pending_from == PendingFrom.created:
                    status, msg = 500, "_msg_grant_pending_created"

                raise ErrAccessDocumentPending.httpexception(
                    msg,
                    status,
                    uuid_grant=grant.uuid,
                    level_grant=grant.level,
                    pending_from=pending_from,
                    **detail,
                )
            case Grant(deleted=deleted) as grant:
                if not deleted:
                    if grant.level.value < level.value:
                        raise ErrAccessDocumentGrantInsufficient.httpexception(
                            "_msg_insufficient",
                            403,
                            uuid_grant=grant.uuid,
                            level_grant=grant.level,
                            **detail,
                        )
                    do_grant(grant)
                    return self
                elif not exclude_deleted:
                    do_grant(grant)
                    return self
                else:
                    raise ErrAccessDocumentGrantBase.httpexception(
                        "_msg_dne",
                        410,
                        **detail,
                    )
            # NOTE: Server has become a teapot: Should never happen!
            case _:
                raise ErrAccessDocumentGrantBase.httpexception(
                    "_msg_inconcievable",
                    418,
                    **detail,
                    level_grant_required=Level.own,
                )

    def check_sole_owner_document(self, document: "Document") -> Self: ...

    def check_can_access_event(self, event: Event, status_code: int = 403) -> Self:
        if self.uuid != event.uuid_user:
            raise ErrAccessEvent.httpexception(
                "_msg_not_owner", 403, uuid_event=event.uuid, uuid_user=self.uuid
            )

        return self


class Collection(SearchableTableMixins, Base):
    __tablename__ = "collections"

    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(fields.LENGTH_NAME))
    description: Mapped[str] = mapped_column(
        String(fields.LENGTH_DESCRIPTION),
        nullable=True,
    )

    # NOTE: This corresponds to `User.collections`.
    user: Mapped[User] = relationship(
        primaryjoin="User.id==Collection.id_user",
        back_populates="collections",
    )

    # NOTE: Deletion is included here since this used to read collection
    #       documents.
    documents: Mapped[List["Document"]] = relationship(
        # collection_class=attribute_keyed_dict("name"),
        secondary=AssocCollectionDocument.__table__,
        back_populates="collections",
        primaryjoin="and_(Collection.id==AssocCollectionDocument.id_collection, AssocCollectionDocument.deleted == false())",
        secondaryjoin="and_(Document.deleted == false(), Document.id==AssocCollectionDocument.id_document)",
    )

    @property
    def uuid_user(self) -> str:
        session = self.get_session()
        q = select(User.uuid).where(User.id == self.id_user)
        res = session.execute(q).scalar()
        if res is None:
            raise ValueError("Inconcievable!")
        return res

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
    name: Mapped[str] = mapped_column(String(fields.LENGTH_NAME))
    description: Mapped[str] = mapped_column(String(fields.LENGTH_DESCRIPTION))
    content: Mapped[str] = mapped_column(mysql.BLOB(fields.LENGTH_CONTENT))
    format: Mapped[Format] = mapped_column(Enum(Format))

    edits: Mapped[List["Edit"]] = relationship(
        cascade="all, delete",
        back_populates="document",
        primaryjoin="Document.id==Edit.id_document",
    )
    users: Mapped[List[User]] = relationship(
        # collection_class=attribute_keyed_dict("name"),
        secondary=AssocUserDocument.__table__,
        back_populates="documents",
        secondaryjoin="User.id==AssocUserDocument.id_user",
        primaryjoin="AssocUserDocument.id_document==Document.id",
    )
    collections: Mapped[List[Collection]] = relationship(
        # collection_class=attribute_keyed_dict("name"),
        secondary=AssocCollectionDocument.__table__,
        back_populates="documents",
    )

    # ----------------------------------------------------------------------- #
    # Queries

    def q_conds_grants(
        self,
        user_uuids: Set[str] | None = None,
        level: ResolvableLevel | None = None,
        exclude_deleted: bool = True,
        pending: bool | None = None,
        exclude_pending: bool = True,
        pending_from: PendingFrom | None = None,
    ) -> ColumnElement[bool]:
        """

        :param pending: Specify a value for pending.
        :param exclude_pending: Specify if all grants should be returned
            regardless of their pending status.
        """
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
            level = Level.resolve(level)
            cond = and_(cond, AssocUserDocument.level >= level.value)

        match (pending, exclude_pending):
            case (True, True):
                msg = "`pending` and `exclude_pending` cannot both be ``True``."
                raise ValueError(msg)
            case (bool() as pending, False):
                cond = and_(cond, Grant.pending == (true() if pending else false()))
            case (None | False, True):
                cond = and_(cond, Grant.pending == false())

        if pending_from is not None:
            cond = and_(cond, Grant.pending_from == pending_from)

        return cond

    def q_select_grants(
        self,
        user_uuids: Set[str] | None = None,
        level: ResolvableLevel | None = None,
        exclude_deleted: bool = True,
        exclude_pending: bool = True,
        pending: bool = False,
        pending_from: PendingFrom | None = None,
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
            exclude_pending=exclude_pending,
            pending_from=pending_from,
        )
        return select(Grant).join(Document).join(User).where(conds)

    def q_select_users(
        self,
        user_uuids: Set[str] | None = None,
        level: ResolvableLevel | None = None,
        exclude_deleted: bool = True,
        exclude_pending: bool = True,
        pending: bool = False,
        pending_from: PendingFrom | None = None,
    ) -> Select:
        """Select user uuids for this document.

        For parameter descriptions, see :meth:`q_select_grants`.
        """
        q = (
            select(User)
            .join(AssocUserDocument)
            .where(
                self.q_conds_grants(
                    user_uuids=user_uuids,
                    level=level,
                    exclude_deleted=exclude_deleted,
                    exclude_pending=exclude_pending,
                    pending=pending,
                    pending_from=pending_from,
                )
            )
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

    def q_select_edits(
        self,
        exclude_deleted: bool = True,
        before: int | None = None,
        after: int | None = None,
        limit: int | None = None,
    ) -> Select:

        conds = []
        if before is not None:
            conds.append(Event.timestamp <= before)
        if after is not None:
            conds.append(Event.timestamp >= after)

        q_uuids = select(Event.uuid_obj).where(
            Event.kind_obj == KindObject.edit,
            Event.kind == KindEvent.update,
            Event.detail == Event.detail_document_editted,
            *conds,
        )
        q = select(Edit).where(Edit.uuid.in_(q_uuids))
        if exclude_deleted:
            q = q.where(Edit.deleted == false())
        if limit is not None:
            q = q.limit(limit)

        return q

    @classmethod
    def q_select_documents(
        cls,
        user: User,
        uuid_documents: Set[str] | None = None,
        exclude_deleted: bool = True,
        before: int | None = None,
        after: int | None = None,
        limit: int | None = None,
    ) -> Select:

        conds = []
        if before is not None:
            conds.append(Event.timestamp <= before)
        if after is not None:
            conds.append(Event.timestamp >= after)

        q_uuids = (
            select(Event.uuid_obj)
            .where(
                Event.kind_obj == KindObject.document,
                Event.kind == KindEvent.update,
                Event.detail == Event.detail_document_editted,
                *conds,
            )
            .distinct()
        )
        if limit is not None:
            q_uuids = q_uuids.limit(limit)

        q = select(cls).where(cls.uuid.in_(q_uuids))
        if exclude_deleted:
            q = q.where(cls.deleted == false())
        if uuid_documents:
            q = q.where(cls.uuid.in_(uuid_documents))

        conds = user.q_conds_grants(uuid_documents)
        q = q.join(Grant).join(User).where(conds)

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
    content: Mapped[int] = mapped_column(mysql.BLOB(fields.LENGTH_CONTENT))
    message: Mapped[str] = mapped_column(String(fields.LENGTH_MESSAGE), nullable=True)

    user: Mapped[User] = relationship(
        primaryjoin="User.id==Edit.id_user",
        back_populates="edits",
    )

    document: Mapped[Document] = relationship(
        primaryjoin="Document.id==Edit.id_document",
        back_populates="edits",
    )

    @property
    def uuid_user(self) -> str:
        session = self.get_session()
        q = select(User.uuid).where(User.id == self.id_user)
        res = session.execute(q).scalar()
        if res is None:
            raise ValueError("Inconcievable!")
        return res

    @property
    def uuid_document(self) -> str:
        session = self.get_session()
        q = select(Document.uuid).where(Document.id == self.id_user)
        res = session.execute(q).scalar()
        if res is None:
            raise ValueError("Inconcievable!")
        return res

    @classmethod
    def q_select_for_user(
        cls,
        user: User,
        uuids: Set[str] | None,
        exclude_deleted: bool = True,
    ) -> Select:
        q_docs = user.q_select_documents(
            uuids,
            level=Level.view,
            exclude_deleted=exclude_deleted,
        )
        q_doc_uuids = select(literal_column("uuid")).select_from(q_docs)
        q_edits = select(Edit).where(Edit.document.uuid.in_(q_doc_uuids))
        if exclude_deleted:
            q_edits = q_edits.where(Edit.deleted == false())

        return q_edits


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
    Event,
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
