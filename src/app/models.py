import enum
from logging import warn
from fastapi import HTTPException, status
import secrets
from sqlalchemy.orm import Session
from datetime import datetime
from typing import (
    Annotated,
    Any,
    Callable,
    Dict,
    Generator,
    List,
    Self,
    Set,
    Tuple,
    Type,
)

from sqlalchemy import (
    CTE,
    ColumnClause,
    CompoundSelect,
    union,
    union_all,
    BinaryExpression,
    ColumnElement,
    Enum,
    ForeignKey,
    Select,
    String,
    and_,
    func,
    literal_column,
    select,
    text,
)
from sqlalchemy.dialects import mysql
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    backref,
    column_property,
    mapped_column,
    object_session,
    relationship,
)
from sqlalchemy.orm.mapped_collection import attribute_keyed_dict

from app import __version__

# =========================================================================== #
# CONSTANTS, ENUMS, ETC.
#
# NOTE: These enums will be used throughout the program and a should be used
#       to create the types needed by fastapi and typer.
#


LENGTH_NAME: int = 96
LENGTH_TITLE: int = 128
LENGTH_DESCRIPTION: int = 256
LENGTH_URL: int = 256
LENGTH_MESSAGE: int = 1024
LENGTH_CONTENT: int = 2**15
LENGTH_FORMAT: int = 8


class Level(enum.Enum):
    # NOTE: Must be consisten with sql
    view = 0
    modify = 1
    own = 2


class LevelStr(str, enum.Enum):
    view = "view"
    modify = "modify"
    own = "own"


class KindEvent(str, enum.Enum):
    create = "create"
    update = "update"
    delete = "delete"
    grant = "grant"
    restore = "restore"


# This maps table names to their corresponding API names.
class KindObject(str, enum.Enum):
    user = "users"
    document = "documents"
    collection = "collections"
    edit = "edits"
    event = "events"
    assignment = "_assocs_collections_documents"
    grant = "_assocs_users_documents"


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
MappedColumnDeleted = Annotated[bool, mapped_column(default=False)]
# =========================================================================== #
# Models and Mixins


class Base(DeclarativeBase):
    def get_session(self) -> Session:
        session = object_session(self)
        if session is None:
            raise HTTPException(418)
        return session

    # NOTE: Only `classmethod`s should need session due to `object_session`.
    @classmethod
    def if_exists(
        cls, session: Session, uuid: str, status: int = 404, msg=None
    ) -> Self:
        m = session.execute(select(cls).where(cls.uuid == uuid)).scalar()
        if m is None:
            detail = dict(
                msg=msg
                if msg is not None
                else f"{cls} with uuid `{uuid}` does not exist."
            )
            detail["uuid"] = uuid
            raise HTTPException(status, detail=detail)
        return m

    @classmethod
    def q_uuid(cls, uuids: set[str]):
        return select(cls).where(cls.uuid.in_(uuids))

    def check_not_deleted(self, status_code: int = 410, msg=None) -> Self:
        if not hasattr(self, "deleted"):
            msg = f"`{self.__class__.__name__}` has no column `deleted`."
            raise ValueError(msg)
        if getattr(self, "deleted"):
            raise HTTPException(status_code, msg="Item is deleted.")
        return self


class MixinsPrimary:
    """Creation and deletion data will go into the table associated with
    :class:`Event`.
    """

    uuid: Mapped[MappedColumnUUID]
    public: Mapped[bool] = mapped_column(default=True)
    deleted: Mapped[bool] = mapped_column(default=False)

    @classmethod
    def q_select_ids(cls, uuids: Set[str]) -> Select:
        return select(cls.id).where(cls.uuid.in_(uuids))


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
    uuid_undo: Mapped[str | None] = mapped_column(ForeignKey("events.uuid"))
    uuid_user: Mapped[str] = mapped_column(ForeignKey("users.uuid"))
    uuid_obj: Mapped[MappedColumnUUID]

    api_origin: Mapped[str] = mapped_column(String(64))
    api_version: Mapped[str] = mapped_column(String(16), default=__version__)
    kind: Mapped[KindEvent] = mapped_column(Enum(KindEvent))
    kind_obj: Mapped[KindObject] = mapped_column(Enum(KindObject))
    detail: Mapped[str] = mapped_column(String(LENGTH_DESCRIPTION), nullable=True)

    children: Mapped[List["Event"]] = relationship("Event", foreign_keys=uuid_parent)
    undo: Mapped["Event"] = relationship("Event", foreign_keys=uuid_undo)

    user: Mapped["User"] = relationship()

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

    # def root(self, session: Session | None = None) -> Self:
    #     if self.uuid_parent is None:
    #         return self
    #
    #     session = session or self.get_session()
    #     return Event.if_exists(session, self.uuid_parent, 500)

    # def flattened(self) -> Generator["Event", None, None]:
    #     yield self
    #     for child in self.children:
    #         yield from child.flattened()

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


class AssocCollectionDocument(Base):
    __tablename__ = "_assocs_collections_documents"

    # NOTE: Since this object supports soft deletion (for the deletion grace
    #       period that will later be implemented) deleted is included.
    deleted: Mapped[MappedColumnDeleted]
    uuid: Mapped[MappedColumnUUID]
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


# NOTE: Should be able to be passed directly into `GrantSchema`.
class AssocUserDocument(Base):
    __tablename__ = "_assocs_users_documents"

    deleted: Mapped[MappedColumnDeleted]
    uuid: Mapped[MappedColumnUUID]
    id_user: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        primary_key=True,
    )
    id_document: Mapped[int] = mapped_column(
        ForeignKey("documents.id"),
        primary_key=True,
    )
    level: Mapped[Level] = mapped_column(Enum(Level))

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


class User(Base, MixinsPrimary):
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
        primaryjoin="and_(User.id==Collection.id_user, Collection.deleted == False)",
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
        primaryjoin="and_(User.id==AssocUserDocument.id_user, Document.deleted == False)",
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
    ) -> ColumnElement[bool]:
        cond = AssocUserDocument.id_user == self.id
        if exclude_deleted:
            cond = and_(
                Document.deleted == False,
                AssocUserDocument.deleted == False,
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
            cond = and_(cond, AssocUserDocument.level >= level.value)

        return cond

    def q_select_grants(
        self,
        document_uuids: None | Set[str] = None,
        level: Level | None = None,
        exclude_deleted: bool = True,
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
        q = (
            select(
                User.uuid.label("uuid_user"),
                Document.uuid.label("uuid_document"),
                AssocUserDocument.uuid.label("uuid"),
                AssocUserDocument.level.label("level"),
            )
            .select_from(User)
            .join(AssocUserDocument)
            .join(Document)
        )
        conds = self.q_conds_grants(document_uuids, level, exclude_deleted)
        q = q.where(conds)
        return q

    def q_select_documents(
        self, document_uuids: Set[str] | None = None, level: Level | None = None
    ) -> Select:
        """Dual to :meth:`q_select_user_uuids`."""

        return (
            select(Document)
            .join(AssocUserDocument)
            .where(
                self.q_conds_grants(document_uuids, level),
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
        #
        # return list(session.execute(q).scalars())

    # ----------------------------------------------------------------------- #
    # Chainables for endpoints.

    # NOTE: Chainable methods should be prefixed with `check_`.
    def check_can_access_collection(self, collection: "Collection") -> Self:
        if not collection.public and collection.id_user != self.id:
            raise HTTPException(
                403,
                detail=dict(
                    msg="User cannot access this collection.",
                    uuid_user=self.uuid,
                    uuid_collection=collection.uuid,
                ),
            )
        return self

    def check_can_access_document(self, document: "Document", level: Level) -> Self:
        session = self.get_session()

        q = self.q_select_grants({document.uuid}, level)
        q_assoc_uuid = select(literal_column("uuid")).select_from(q)
        q_assocs = select(AssocUserDocument).where(
            AssocUserDocument.uuid.in_(q_assoc_uuid)
        )
        # print(q_assocs.compile(session.bind, compile_kwargs={"literal_binds": True}))
        res = session.execute(q_assocs).scalars()
        assocs: List[AssocUserDocument] = list(res)
        # print(res)

        detail = dict(uuid_user=self.uuid, uuid_document=document.uuid)
        if not (n := len(assocs)):
            detail.update(
                msg=f"No grant for document with level `{level.name}`.",
            )
            raise HTTPException(403, detail=detail)
        elif n != 1:
            # Server is a teapot because this is unlikely to ever happen.
            detail.update(msg="There should only be one grant.")
            raise HTTPException(418, detail=detail)
        elif assocs[0].level.value < level.value:
            detail.update(msg=f"User must have grant of level `{level.name}`.")
            raise HTTPException(403, detail=detail)

        return self

    def check_sole_owner_document(self, document: "Document") -> Self:
        ...

    def check_can_access_event(self, event: Event, status_code: int = 403) -> Self:
        if self.uuid != event.uuid_user:
            detail = dict(uuid_event=event.uuid, uuid_user=self.uuid)
            detail.update(msg="User cannot access event.")
            raise HTTPException(status_code, detail=detail)

        return self


class Collection(Base, MixinsPrimary):
    __tablename__ = "collections"

    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
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
        primaryjoin="and_(Collection.id==AssocCollectionDocument.id_collection, AssocCollectionDocument.deleted == False)",
        secondaryjoin="and_(Document.deleted == False, Document.id==AssocCollectionDocument.id_document)",
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
            cond = and_(
                cond,
                AssocCollectionDocument.deleted == False,
            )
        if document_uuids is not None:
            document_ids = Document.q_select_ids(document_uuids)
            cond = and_(cond, AssocCollectionDocument.id_document.in_(document_ids))

        return cond

    def q_select_assignment(
        self,
        document_uuids: Set[str] | None = None,
    ) -> Select:
        q = (
            select(
                AssocCollectionDocument.uuid.label("uuid"),
                Document.uuid.label("uuid_document"),
                Collection.uuid.label("uuid_collection"),
            )
            .select_from(Document)
            .join(AssocCollectionDocument)
            .join(Collection)
        )
        q = q.where(self.q_conds_assignment(document_uuids))
        return q

    def q_select_documents(
        self,
        document_uuids: Set[str] | None = None,
    ) -> Select:
        q = (
            select(Document)
            .join(AssocCollectionDocument)
            .where(
                self.q_conds_assignment(document_uuids),
                Document.deleted == False,
            )
        )
        return q


class Document(Base, MixinsPrimary):
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

    @classmethod
    def q_select_public(
        cls,
        document_uuids: Set[str] | None = None,
    ):
        q = select(cls).where(cls.public)
        if document_uuids is not None:
            q = q.where(
                cls.uuid.in_(document_uuids),
                cls.deleted == False,
            )
        return q

    def q_conds_grants(
        self,
        user_uuids: Set[str] | None = None,
        level: Level | None = None,
        exclude_deleted: bool = True,
    ) -> ColumnElement[bool]:
        exp = AssocUserDocument.id_document == self.id
        if exclude_deleted:
            exp = and_(
                exp,
                AssocUserDocument.deleted == False,
                User.deleted == False,
            )
        if user_uuids is not None:
            exp = and_(
                exp,
                AssocUserDocument.id_user.in_(
                    select(User.id).where(User.uuid.in_(user_uuids))
                ),
            )
        if level is not None:
            exp = and_(exp, AssocUserDocument.level >= level)
        return exp

    def q_select_grants(
        self,
        user_uuids: Set[str] | None = None,
        level: Level | None = None,
        exclude_deleted: bool = True,
    ) -> Select:
        """Query to find grants (AssocUserDocument) for this document.

        To find grants for a user, see the same named method on :class:`User`.

        :param user_uuids: The uuids of the users to select for.
        :param level: The minimal level to select joined entries from.
        """
        return (
            select(
                AssocUserDocument.uuid.label("uuid"),
                AssocUserDocument.level.label("level"),
                Document.uuid.label("uuid_document"),
                User.uuid.label("uuid_user"),
            )
            .select_from(Document)
            .join(AssocUserDocument)
            .join(User)
            .where(
                self.q_conds_grants(
                    user_uuids=user_uuids, level=level, exclude_deleted=exclude_deleted
                )
            )
        )

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


class Edit(Base, MixinsPrimary):
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


class Tables(enum.Enum):
    assignments = AssocCollectionDocument
    grants = AssocUserDocument
    events = Event
    users = User
    collections = Collection
    documents = Document
    edits = Edit


AnyModelBesidesEvent = (
    AssocUserDocument | AssocCollectionDocument | User | Collection | Document | Edit
)
AnyModel = Event | AnyModelBesidesEvent


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
