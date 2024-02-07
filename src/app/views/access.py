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

H = HTTPMethod


class Access(BaseController):

    # ----------------------------------------------------------------------- #
    # User

    def user(
        self,
        resolve_user: ResolvableSingular[User],
        resolve_user_token: ResolvableSingular[User] | None = None,
    ) -> User:
        """See if the token user can view another user.

        Resolve the user and verify that is not deleted.
        """

        user = self.token_user_or(resolve_user).check_not_deleted(410)
        user_token = self.token_user_or(resolve_user_token)

        # NOTE: When `GET` method, if the user is public, return. Otherwise
        #       always check for a token and check the token uuid.
        match self.method:
            case HTTPMethod.GET if not user.public:
                if self.token.uuid != user.uuid:
                    detail = dict(
                        uuid_user_token=user_token.uuid,
                        uuid_user=user.uuid,
                        msg="User is not public.",
                    )
                    raise HTTPException(403, detail=detail)
                return user
            case HTTPMethod.GET:
                return user
            case (
                HTTPMethod.POST | HTTPMethod.PATCH | HTTPMethod.PUT | HTTPMethod.DELETE
            ):
                if user.uuid != user_token.uuid:
                    detail = dict(
                        uuid_user=user.uuid,
                        uuid_user_token=user_token.uuid,
                        msg="Cannot modify other user.",
                    )
                    raise HTTPException(403, detail)
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
        resolve_user_token: ResolvableSingular[User] | None = None,
    ) -> Collection: ...

    @overload
    def collection(
        self,
        resolve_collection: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
    ) -> Tuple[Collection, ...]: ...

    def collection(
        self,
        resolve_collection: Resolvable[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
    ) -> Collection | Tuple[Collection, ...]:

        # NOTE: `exclude_deleted` should only be ``True`` when a force
        #       deletion is occuring.
        def check_one(collection: Collection) -> Collection:
            token_user.check_can_access_collection(collection)
            if exclude_deleted:
                collection = collection.check_not_deleted(410)

            match self.method:
                case H.GET:
                    return collection
                case H.POST | H.DELETE | H.PUT | H.PATCH:
                    if token_user.id != collection.id_user:
                        detail = dict(
                            uuid_user_token=self.token.uuid,
                            uuid_collection=collection.uuid,
                            msg="User cannot access private collection.",
                        )

                        # Not sure how this happens on occasion.
                        if collection.id_user is not None:
                            detail.update(msg="Collection has no owner.")
                            raise HTTPException(418, detail=detail)

                        raise HTTPException(403, detail=detail)
                    return collection
                case _:
                    raise ValueError(f"Cannot handle HTTPMethod `{self.method}`.")

        token_user = self.token_user_or(resolve_user_token)
        collections: Collection | Tuple[Collection, ...]
        collections = Collection.resolve(self.session, resolve_collection)

        match collections:
            case Collection():
                return check_one(collections)
            case tuple():
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
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
    ) -> Document: ...

    @overload
    def document(
        self,
        resolve_document: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
    ) -> Tuple[Document, ...]: ...

    def document(
        self,
        resolve_document: Resolvable[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
    ) -> Document | Tuple[Document, ...]:

        level = level if level is not None else self.level
        token_user = self.token_user_or(resolve_user_token)
        documents = Document.resolve(self.session, resolve_document)
        # print()
        # print("========================================================")
        # print("document")
        # print()
        # print(f"{level=}")
        # print(f"{token_user.uuid=}")
        # print(f"{documents=}")
        # print()

        # NOTE: Exclude deleted is only required for force deletion.
        def check_one(document: Document) -> Document:
            token_user.check_can_access_document(document, level)
            if exclude_deleted:
                document = document.check_not_deleted(410)
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
        resolve_user_token: ResolvableSingular[User] | None = None,
    ): ...

    # ----------------------------------------------------------------------- #
    # Assignments

    def assignment_collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        resolve_documents: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
    ) -> Tuple[Collection, Tuple[Document, ...]]:

        # NOTE: Keep `token_user` here so that the user is checked.
        token_user = self.token_user_or(resolve_user_token)
        collection = self.collection(
            resolve_collection,
            exclude_deleted=exclude_deleted,
            resolve_user_token=token_user,
        )
        documents = self.document(
            resolve_documents,
            level=level or self.level,
            exclude_deleted=exclude_deleted,
            resolve_user_token=token_user,
        )
        return collection, documents

    def assignment_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_collections: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
    ) -> Tuple[Document, Tuple[Collection, ...]]:

        token_user = self.token_user_or(resolve_user_token)
        document = self.document(
            resolve_document,
            level=level or self.level,
            exclude_deleted=exclude_deleted,
            resolve_user_token=token_user,
        )
        collections = self.collection(
            resolve_collections,
            exclude_deleted=exclude_deleted,
            resolve_user_token=token_user,
        )

        return document, collections
