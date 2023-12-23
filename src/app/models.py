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


class Collection(Base, MixinsSecondary):
    __tablename__ = "collections"

    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(LENGTH_NAME))
    description: Mapped[str] = mapped_column(
        String(LENGTH_DESCRIPTION),
        nullable=True,
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
    id_document: Mapped[int] = mapped_column(ForeignKey("users.id"))
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
