from http import HTTPMethod
from typing import Annotated, List, Sequence, Set, Tuple, TypeAlias, overload

from app.auth import Token
from app.depends import DependsToken
from app.models import (
    AssocCollectionDocument,
    AssocUserDocument,
    ChildrenAssignment,
    Collection,
    Document,
    Edit,
    Level,
    LevelHTTP,
    Resolvable,
    ResolvableMultiple,
    ResolvableSingular,
    User,
)
from app.views import args
from app.views.base import BaseController
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session


class Access(BaseController):

    # ----------------------------------------------------------------------- #
    # User

    def user(self, resolve_user: ResolvableSingular[User]) -> User:
        """See if the token user can view another user.

        Resolve the user and verify that is not deleted.
        """

        user = self.token_user_or(resolve_user).check_not_deleted(410)
        token = self.token

        if self.method != HTTPMethod.GET:
            if user.uuid != token.uuid:
                detail = dict(
                    uuid_user=token.uuid,
                    uuid_user_token=token.uuid,
                    msg="Cannot modify other user.",
                )
                raise HTTPException(403, detail)
            return user

        # NOTE: When `GET` method, if the user is public, return. Otherwise
        #       always check for a token and check the token uuid.
        token = self.token
        match self.method:
            case HTTPMethod.GET if not user.public:
                detail = dict(uuid_user=user.uuid, msg="User is not public.")
                raise HTTPException(403, detail=detail)
            case HTTPMethod.GET:
                return user
            case _ as bad:
                raise ValueError(f"Cannot yet method `{bad}`.")

    # ----------------------------------------------------------------------- #
    # Collection

    @overload
    def collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> Collection: ...

    @overload
    def collection(
        self,
        resolve_collection: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> Tuple[Collection, ...]: ...

    def collection(
        self,
        resolve_collection: Resolvable[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> Collection | Tuple[Collection, ...]:

        # NOTE: `exclude_deleted` should only be ``True`` when a force
        #       deletion is occuring.
        def check_one(collection: Collection) -> Collection:
            if exclude_deleted:
                collection = collection.check_not_deleted(410)
            token_user.check_can_access_collection(collection)
            return collection

        token_user = self.token_user_or(resolve_user)
        collections: Collection | Tuple[Collection, ...]
        collections = Collection.resolve(self.session, resolve_collection)

        match collections:
            case Collection():
                return check_one(collections)
            case list():
                return tuple(map(check_one, collections))
            case _ as bad:
                raise ValueError(
                    "`collections must be a `Collection` or `tuple` of "
                    f"`Collection`s (got `{type(bad)}`)."
                )

    # ----------------------------------------------------------------------- #
    # Documents

    @overload
    def document(
        self,
        resolve_document: ResolvableSingular[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
        level: Level | None = None,
    ) -> Document: ...

    @overload
    def document(
        self,
        resolve_document: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
        level: Level | None = None,
    ) -> Tuple[Document, ...]: ...

    def document(
        self,
        resolve_document: Resolvable[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
        level: Level | None = None,
    ) -> Document | Tuple[Document, ...]:

        level = level if level is not None else self.level
        token_user = self.token_user_or(resolve_user)
        documents = Document.resolve(self.session, resolve_document)

        # NOTE: Exclude deleted is only required for force deletion.
        def check_one(document: Document) -> Document:
            if exclude_deleted:
                print(document)
                document = document.check_not_deleted(410)
            token_user.check_can_access_document(document, level)
            return document

        match documents:
            case tuple() as documents:
                return tuple(map(check_one, documents))
            case Document():
                return check_one(documents)
            case _ as bad:
                msg = f"Unexpected input of type `{type(bad)}`."
                raise ValueError(msg)

    # ----------------------------------------------------------------------- #
    def edit(
        self,
        resolve_edit: Resolvable[Edit],
        *,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
    ): ...

    # ----------------------------------------------------------------------- #
    # Assignments

    def assignment_collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        resolve_documents: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
        level: Level | None = None,
    ) -> Tuple[Collection, Tuple[Document, ...]]:

        # NOTE: Keep `token_user` here so that the user is checked.
        token_user = self.token_user_or(resolve_user)
        collection = self.collection(
            resolve_collection,
            exclude_deleted=exclude_deleted,
            resolve_user=token_user,
        )
        documents = self.document(
            resolve_documents,
            level=level or self.level,
            exclude_deleted=exclude_deleted,
            resolve_user=token_user,
        )
        return collection, documents

    def assignment_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_collections: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
        level: Level | None = None,
    ) -> Tuple[Document, Tuple[Collection, ...]]:

        token_user = self.token_user_or(resolve_user)
        document = self.document(
            resolve_document,
            level=level or self.level,
            exclude_deleted=exclude_deleted,
            resolve_user=token_user,
        )
        collections = self.collection(
            resolve_collections,
            exclude_deleted=exclude_deleted,
            resolve_user=token_user,
        )

        return document, collections
