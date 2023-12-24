from datetime import datetime
from typing import Dict, List

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import DeclarativeBase, Mapped, backref, mapped_column, relationship
from sqlalchemy.orm.mapped_collection import attribute_keyed_dict

LENGTH_NAME: int = 64
LENGTH_TITLE: int = 128
LENGTH_DESCRIPTION: int = 256
LENGTH_URL: int = 256
LENGTH_CONTENT: int = 2**15


class Base(DeclarativeBase):
    ...


class MixinsPrimary:
    _created_timestamp: Mapped[int] = mapped_column(
        default=(_now := lambda: datetime.timestamp(datetime.now())),
    )
    _updated_timestamp: Mapped[int] = mapped_column(default=_now)


class MixinsSecondary(MixinsPrimary):
    _created_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    _updated_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )


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

    edits: Mapped[List["DocumentHistory"]] = relationship(
        cascade="all, delete",
        back_populates="user",
        primaryjoin="User.id==DocumentHistory.id_user",
    )


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


class Document(Base, MixinsSecondary):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(LENGTH_NAME))
    description: Mapped[str] = mapped_column(String(LENGTH_DESCRIPTION))
    content: Mapped[str] = mapped_column(mysql.BLOB(LENGTH_CONTENT))
    content_fmt: Mapped[str] = mapped_column(String(8))


class AssocCollectionDocument(Base, MixinsSecondary):
    __tablename__ = "_assocs_collections_documents"

    id_user: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        primary_key=True,
    )
    id_collection: Mapped[int] = mapped_column(
        ForeignKey("collections.id"),
        primary_key=True,
    )


class AssocUserDocument(Base, MixinsSecondary):
    __tablename__ = "_assocs_user_documents"

    id_user: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        primary_key=True,
    )
    id_document: Mapped[int] = mapped_column(
        ForeignKey("documents.id"),
        primary_key=True,
    )


class DocumentHistory(Base, MixinsSecondary):
    __tablename__ = "document_histories"

    id: Mapped[int] = mapped_column(primary_key=True)
    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"))
    id_document: Mapped[int] = mapped_column(ForeignKey("documents.id"))
    content_previous: Mapped[int] = mapped_column(mysql.BLOB(LENGTH_CONTENT))

    user: Mapped[User] = relationship(
        primaryjoin="User.id==DocumentHistory.id_user",
        back_populates="edits",
    )


__all__ = (
    "Base",
    "User",
    "Collection",
    "AssocCollectionDocument",
    "AssocUserDocument",
    "Document",
    "DocumentHistory",
)
