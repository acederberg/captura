from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

LENGTH_NAME: int = 64
LENGTH_TITLE: int = 128
LENGTH_DESCRIPTION: int = 256
LENGTH_URL: int = 256
LENGTH_CONTENT: int = 2**15


class Base(DeclarativeBase):
    _created_timestamp: Mapped[int] = mapped_column(
        default=(now := lambda: datetime.timestamp(datetime.now())),
    )
    _created_by_user_id: Mapped[int]
    _updated_timestamp: Mapped[int] = mapped_column(default=now)
    _updated_by_user_id: Mapped[int]


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(LENGTH_NAME), unique=True)
    description: Mapped[str] = mapped_column(String(LENGTH_DESCRIPTION))
    url_image: Mapped[str] = mapped_column(String(LENGTH_URL))
    url: Mapped[str] = mapped_column(String(LENGTH_URL))


class Collection(Base):
    __tablename__ = "collections"

    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"))
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(LENGTH_NAME))
    description: Mapped[str] = mapped_column(String(LENGTH_DESCRIPTION))


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(LENGTH_NAME))
    description: Mapped[str] = mapped_column(String(LENGTH_DESCRIPTION))
    content: Mapped[str] = mapped_column(mysql.BLOB(LENGTH_CONTENT))
    content_fmt: Mapped[str] = mapped_column(String(8))


class AssocCollectionDocument(Base):
    __tablename__ = "_assocs_collections_documents"

    id_user: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        primary_key=True,
    )
    id_collection: Mapped[int] = mapped_column(
        ForeignKey("collections.id"),
        primary_key=True,
    )


class AssocUserDocument(Base):
    __tablename__ = "_assocs_user_documents"

    id_user: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        primary_key=True,
    )
    id_document: Mapped[int] = mapped_column(
        ForeignKey("documents.id"),
        primary_key=True,
    )


class DocumentHistory(Base):
    __tablename__ = "documents_histories"

    id: Mapped[int] = mapped_column(primary_key=True)
    content_previous: Mapped[int] = mapped_column(mysql.BLOB(LENGTH_CONTENT))


__all__ = (
    "Base",
    "User",
    "Collection",
    "AssocCollectionDocument",
    "AssocUserDocument",
    "Document",
    "DocumentHistory",
)
