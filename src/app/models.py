import enum
import secrets
from datetime import datetime
from typing import Dict, List, Set

from sqlalchemy import Enum, ForeignKey, String
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import (DeclarativeBase, Mapped, backref, mapped_column,
                            relationship)
from sqlalchemy.orm.mapped_collection import attribute_keyed_dict

LENGTH_NAME: int = 64
LENGTH_TITLE: int = 128
LENGTH_DESCRIPTION: int = 256
LENGTH_URL: int = 256
LENGTH_MESSAGE: int = 1024
LENGTH_CONTENT: int = 2**15
LENGTH_FORMAT: int = 8


class Base(DeclarativeBase):
    ...


class MixinsPrimary:
    uuid: Mapped[str] = mapped_column(
        String(16), default=lambda: secrets.token_urlsafe(8), index=True
    )

    _created_timestamp: Mapped[int] = mapped_column(
        default=(_now := lambda: datetime.timestamp(datetime.now())),
    )
    _updated_timestamp: Mapped[int] = mapped_column(default=_now)
    _deleted_timestamp: Mapped[int] = mapped_column(nullable=True)
    _deleted: Mapped[bool] = mapped_column(default=False)


class MixinsSecondary(MixinsPrimary):
    _deleted_by_user_uuid: Mapped[str] = mapped_column(
        ForeignKey("users.uuid"),
        nullable=True,
    )
    _created_by_user_uuid: Mapped[str] = mapped_column(
        ForeignKey("users.uuid"), nullable=True
    )
    _updated_by_user_uuid: Mapped[str] = mapped_column(
        ForeignKey("users.uuid"), nullable=True
    )


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


class Level(enum.Enum):
    view = 0
    modify = 10
    own = 20


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
        # primaryjoin="User.id==AssocUserDocument.id_user, AssocUserDocument.id_document=Document.id, "
    )

    def documents_by_level(self, level: Level, document_uuids: Set[str]) -> Dict:

        for document in self.documents.values():
            
        return 
        # return {
        #     document_name: document 
        #     for document_name, document in self.documents.items()
        #     if document.uuid not in document_uuids or (
        #         document.uuid in document_uuids
        #         and document.
        #     )
        # }


class Collection(Base, MixinsSecondary):
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


class Document(Base, MixinsSecondary):
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
    )
    collections: Mapped[Dict[str, Collection]] = relationship(
        collection_class=attribute_keyed_dict("name"),
        secondary=AssocCollectionDocument.__table__,
        back_populates="documents",
    )


class Edit(Base, MixinsSecondary):
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
