import enum
from logging import warn
from fastapi import HTTPException
import secrets
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Annotated, Any, Dict, List, Self, Set, Tuple

from sqlalchemy import (
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

LENGTH_NAME: int = 64
LENGTH_TITLE: int = 128
LENGTH_DESCRIPTION: int = 256
LENGTH_URL: int = 256
LENGTH_MESSAGE: int = 1024
LENGTH_CONTENT: int = 2**15
LENGTH_FORMAT: int = 8


class Level(enum.Enum):
    view = 0
    modify = 10
    own = 20


class LevelStr(str, enum.Enum):
    view = "view"
    modify = "modify"
    own = "own"


class KindEvent(str, enum.Enum):
    create = "create"
    update = "update"
    delete = "delete"
    grant = "grant"


# This maps table names to their corresponding API names.
class KindObject(str, enum.Enum):
    user = "users"
    document = "documents"
    collection = "collections"
    edit = "edits"
    event = "events"
    assignment = "_assocs_collections_documents"
    grant = "_assocs_users_documents"


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
#       keys for some resources (e.g. `AssocUserDocument`. See
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


class MixinsPrimary:
    """Creation and deletion data will go into the table associated with
    :class:`Event`.
    """

    uuid: Mapped[MappedColumnUUID]
    public: Mapped[bool] = mapped_column(default=True)
    deleted: Mapped[bool] = mapped_column(default=False)

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
    uuid_user: Mapped[str] = mapped_column(ForeignKey("users.uuid"))
    uuid_obj: Mapped[MappedColumnUUID]
    kind: Mapped[KindEvent] = mapped_column(Enum(KindEvent))
    kind_obj: Mapped[KindObject] = mapped_column(Enum(KindObject))
    detail: Mapped[str] = mapped_column(String(LENGTH_DESCRIPTION), nullable=True)

    children: Mapped[List["Event"]] = relationship("Event")
    api_origin: Mapped[str] = mapped_column(String(64))
    api_version: Mapped[str] = mapped_column(String(16), default=__version__)

    user: Mapped["User"] = relationship()


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


class AssocUserDocument(Base):
    __tablename__ = "_assocs_users_documents"

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

    # This should be a dictionary of collection names mapping to lists of
    # article names.

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
    ) -> ColumnElement[bool]:
        cond = AssocUserDocument.id_user == self.id
        if document_uuids is not None:
            cond = and_(
                cond,
                AssocUserDocument.id_document.in_(
                    select(Document.id).where(Document.uuid.in_(document_uuids))
                ),
            )
        if level is not None:
            cond = and_(cond, AssocUserDocument.level >= level)

        return cond

    def q_select_grants(
        self,
        document_uuids: None | Set[str] = None,
        level: Level | None = None,
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
        q = q.where(self.q_conds_grants(document_uuids, level))
        return q

    def q_select_documents(
        self, document_uuids: Set[str] | None = None, level: Level | None = None
    ) -> Select:
        """Dual to :meth:`q_select_user_uuids`."""

        return (
            select(Document)
            .join(AssocUserDocument)
            .where(self.q_conds_grants(document_uuids, level))
        )

    def q_select_documents_exclusive(self, document_uuids: Set[str] | None = None):
        # q = select(Document.id).where(
        #     Document.id == AssocUserDocument.id_document,
        #     AssocUserDocument.level == Level.own,
        #     AssocUserDocument.id_user == self.id,
        # )
        # q = select(AssocUserDocument.id_document.label("id_document")).where(
        #     self.q_conds_grants(document_uuids, level)
        # )

        level = Level.own
        q = self.q_select_documents(document_uuids, level)

        # literally = literal_column("id_document")
        # q = (
        #     select(literally, func.count(literally).label("owner_count"))
        #     .select_from(q)
        #     .group_by(literally)
        # )
        q = (
            select(Document.id, func.count(Document.id).label("owner_count"))
            .select_from(q)
            .group_by(Document.id)
        )

        q = select(Document.id).select_from(q).where(literal_column("owner_count") == 1)
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
        assocs: List[Level] = list(
            session.execute(
                select(AssocUserDocument.level).where(
                    AssocUserDocument.id_user == self.id,
                    AssocUserDocument.id_document == document.id,
                )
            ).scalars()
        )
        detail = dict(uuid_user=self.uuid, uuid_document=document.uuid)
        if not (n := len(assocs)):
            detail.update(
                msg="No grant for document.",
            )
            raise HTTPException(403, detail=detail)
        elif n != 1:
            # Server is a teapot because this is unlikely to ever happen.
            detail.update(msg="There should only be one grant.")
            raise HTTPException(418, detail=detail)
        elif assocs[0].value < Level.own.value:
            detail.update(msg=f"User must have grant of level `{level.name}`.")
            raise HTTPException(403, detail=detail)

        return self

    def check_sole_owner_document(self, document: "Document") -> Self:
        ...


class Collection(Base, MixinsPrimary):
    __tablename__ = "collections"

    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(LENGTH_NAME), unique=True)
    description: Mapped[str] = mapped_column(
        String(LENGTH_DESCRIPTION),
        nullable=True,
    )

    # NOTE: This corresponds to `User.collections`.
    user: Mapped[User] = relationship(
        primaryjoin="User.id==Collection.id_user",
        back_populates="collections",
        # cascade="all, delete-orphan",
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
        self, document_uuids: Set[str] | None = None
    ) -> ColumnElement[bool]:
        # NOTE: To add the conditions for document select (like level) use
        #       `q_conds_assoc`.
        cond = AssocCollectionDocument.id_collection == self.id
        if document_uuids is not None:
            document_ids = Document.q_select_ids(document_uuids)
            cond = and_(cond, AssocCollectionDocument.id_document.in_(document_ids))

        return cond

    def q_select_assignment(self, document_uuids: Set[str] | None = None) -> Select:
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
            .where(self.q_conds_assignment(document_uuids))
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

    def q_conds_grants(
        self, user_uuids: Set[str] | None = None, level: Level | None = None
    ) -> ColumnElement[bool]:
        exp = AssocUserDocument.id_document == self.id
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
        self, user_uuids: Set[str] | None = None, level: Level | None = None
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
            .where(self.q_conds_grants(user_uuids=user_uuids, level=level))
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


__all__ = (
    "Base",
    "User",
    "Collection",
    "AssocCollectionDocument",
    "AssocUserDocument",
    "Document",
    "Edit",
)
