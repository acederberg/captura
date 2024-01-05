import enum
import secrets
from datetime import datetime
from typing import Annotated, Dict, List, Set

from sqlalchemy import Enum, ForeignKey, String, select
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

# =========================================================================== #
# CONSTANTS, ETC.

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


class EventKind(str, enum.Enum):
    create = "create"
    update = "update"
    delete = "delete"
    grant = "grant"


class ObjectKind(str, enum.Enum):
    user = "users"
    document = "documents"
    collection = "collections"
    edit = "edits"
    assoc_user_document = "_assocs_user_documents"
    assoc_user_collection = "_assocs_user_collections"


MappedColumnUUID = Annotated[
    str,
    mapped_column(String(16), default=lambda: secrets.token_urlsafe(8), index=True),
]
# =========================================================================== #
# Models and Mixins


class Base(DeclarativeBase):
    ...


class MixinsPrimary:
    """Creation and deletion data will go into the table associated with
    :class:`Event`.
    """

    uuid: Mapped[MappedColumnUUID]
    public: Mapped[bool] = mapped_column(default=True)
    deleted: Mapped[bool] = mapped_column(default=False)


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

    uuid_parent: Mapped[str] = mapped_column(ForeignKey("events.uuid"), nullable=True)
    uuid: Mapped[MappedColumnUUID] = mapped_column(primary_key=True)
    uuid_user: Mapped[str] = mapped_column(ForeignKey("users.uuid"))
    uuid_obj: Mapped[MappedColumnUUID]
    kind: Mapped[EventKind] = mapped_column(Enum(EventKind))
    kind_obj: Mapped[ObjectKind] = mapped_column(Enum(ObjectKind))
    detail: Mapped[str] = mapped_column(String(LENGTH_DESCRIPTION), nullable=True)


class AssocCollectionDocument(Base, MixinsPrimary):
    __tablename__ = "_assocs_collections_documents"

    id_document: Mapped[int] = mapped_column(
        ForeignKey("documents.id"),
        primary_key=True,
    )

    id_collection: Mapped[int] = mapped_column(
        ForeignKey("collections.id"),
        primary_key=True,
    )


class AssocUserDocument(Base, MixinsPrimary):
    __tablename__ = "_assocs_user_documents"

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

    id: Mapped[int] = mapped_column(primary_key=True)
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
        collection_class=attribute_keyed_dict("name"),
        cascade="all, delete",
        back_populates="user",
        primaryjoin="User.id==Collection.id_user",
    )

    edits: Mapped[List["Edit"]] = relationship(
        # cascade="all, delete",
        back_populates="user",
        primaryjoin="User.id==Edit.id_user",
    )

    documents: Mapped[Dict[str, "Document"]] = relationship(
        collection_class=attribute_keyed_dict("name"),
        secondary=AssocUserDocument.__table__,
        back_populates="users",
        primaryjoin="User.id==AssocUserDocument.id_user",
        secondaryjoin="AssocUserDocument.id_document==Document.id",
    )

    def document_uuids(
        self, level: Level, verify_uuids: Set[str] | None = None
    ) -> Set[str]:
        """Get the UUIDs of the documents to which this user is granted
        permissions explicitly through :class:`AssocUserDocument` entries at
        :param:`level`.

        This is mostly used to verify ownership of documents, thus a set is
        returned so that checking membership is fast.

        In particular this is needed for

        .. code:: HTTP

            PATCH /users/{self.uuid}/grant?level={level.name}&uuid_document=...

        where it must be verified that a granter has sufficient permissions
        (**own**) to assign the grantee access.

        :param level: The level to match against.
        :param verify: Document UUIDs to verify level of. This makes the
            results returned smaller. Object UUIDs are and ``INDEX`` so
            searching is not too expensive and generally this set will be
            smaller (there will be restrictions implemented using
            ``fastapi.Query`` for untrusted inputs).
        :returns: A set of document object UUIDs at :param:`level` when
            :param:`verify_uuids` is ``None``. Otherwise look for documents with
            uuids in the provided set of uuids that are below the specified level
            and return them.
        """
        session = object_session(self)
        if session is None:
            raise ValueError("Session is required.")

        q_document_ids = select(AssocUserDocument.id_document)

        # NOTE: If ``verify_uuids`` is ``None``, then just compare the level
        #       given to any association. This is like a level set of sorts (
        #       where the mapping is from a document to its level). If it is
        #       not ``None``, look for document ids that are not of a high
        #       enough level.
        conds = (
            (AssocUserDocument.level == level,)
            if verify_uuids is None
            else (
                AssocUserDocument.id_document.in_(
                    select(Document.id).where(Document.uuid.in_(verify_uuids))
                ),
                AssocUserDocument.level < level,
            )
        )
        q_document_ids = q_document_ids.where(
            AssocUserDocument.id_user == self.id, *conds
        )
        q_document_uuids = select(Document.uuid).where(Document.id.in_(q_document_ids))
        return set(session.execute(q_document_uuids).scalars())


class Collection(Base, MixinsPrimary):
    __tablename__ = "collections"

    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(LENGTH_NAME), primary_key=True)
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

    documents: Mapped[Dict[str, "Document"]] = relationship(
        collection_class=attribute_keyed_dict("name"),
        secondary=AssocCollectionDocument.__table__,
        back_populates="collections",
    )


class Document(Base, MixinsPrimary):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(primary_key=True)
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

    def get_user_levels(self, verify_uuids: Set[str]) -> Dict[str, Level]:
        q = (
            select(AssocUserDocument.level, User.uuid)
            .join(User)
            .where(
                User.uuid.in_(verify_uuids),
                AssocUserDocument.id_document == self.id,
            )
        )
        session = object_session(self)
        if session is None:
            raise ValueError("Object missing session.")
        return {row.uuid: row.level for row in session.execute(q)}


class Edit(Base, MixinsPrimary):
    __tablename__ = "edits"

    id: Mapped[int] = mapped_column(primary_key=True)
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
