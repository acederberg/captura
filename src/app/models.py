from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

LENGTH_NAME: int = 64
LENGTH_TITLE: int = 128
LENGTH_DESCRIPTION: int = 256
LENGTH_CONTENT: int = 2**15


class Base(DeclarativeBase):
    _created_timestamp: Mapped[int] = mapped_column(
        positive=True,
        default=(now := lambda: datetime.timestamp(datetime.now())),
    )
    _created_by_user_id: Mapped[int]
    _updated_timestamp: Mapped[int] = mapped_column(positive=True, default=now)
    _updated_by_user_id: Mapped[int]


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, positive=True)
    name: Mapped[str] = mapped_column(String(LENGTH_NAME))
    description: Mapped[str] = mapped_column(String(LENGTH_DESCRIPTION))
    url_image: Mapped[str]
    url: Mapped[str]


class Collection(Base):
    __tablename__ = "collections"

    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"))
    id: Mapped[int] = mapped_column(primary_key=True, positive=True)
    name: Mapped[str] = mapped_column(String(LENGTH_NAME))
    description: Mapped[str] = mapped_column(String(LENGTH_DESCRIPTION))


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(primary_key=True, positive=True)
    name: Mapped[str] = mapped_column(String(LENGTH_NAME))
    description: Mapped[str] = mapped_column(String(LENGTH_DESCRIPTION))
    content: Mapped[str] = mapped_column(String(LENGTH_CONTENT))
    content_fmt: Mapped[str] = mapped_column(String(8))


class AssocCollectionDocument(Base):
    __tablename__ = "_assocs_collections_documents"

    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"))
    id_collection: Mapped[int] = mapped_column(ForeignKey("collections.id"))


class AssocUserDocument(Base):
    __tablename__ = "_assocs_user_documents"

    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"))
    id_document: Mapped[int] = mapped_column(ForeignKey("documents.id"))


class DocumentHistory(Base):
    __tablename__ = "documents_histories"

    id: Mapped[int] = mapped_column(primary_key=True, positive=True)
    content_previous: Mapped[int] = mapped_column(String(LENGTH_CONTENT))


__all__ = (
    "Base",
    "User",
    "Collection",
    "AssocCollectionDocument",
    "AssocUserDocument",
    "Document",
    "DocumentHistory",
)
