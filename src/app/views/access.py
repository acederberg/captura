from http import HTTPMethod
from typing import Annotated, Any, Dict, List, Sequence, Set, Tuple, TypeAlias, overload

from app.auth import Token
from app.depends import DependsToken
from app.models import (
    AssocCollectionDocument,
    AssocUserDocument,
    ChildrenAssignment,
    Collection,
    Document,
    Edit,
    Grant,
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
AccessAssignmentResult = (
    Tuple[Collection, Tuple[Document, ...]] | Tuple[Document, Tuple[Collection, ...]]
)


class Access(BaseController):

    # ----------------------------------------------------------------------- #
    # User
    @overload
    def user(
        self,
        resolve_user: ResolvableMultiple[User],
        resolve_user_token: ResolvableSingular[User] | None = None,
    ) -> Tuple[User, ...]: ...

    @overload
    def user(
        self,
        resolve_user: ResolvableSingular[User],
        resolve_user_token: ResolvableSingular[User] | None = None,
    ) -> User: ...

    def user(
        self,
        resolve_user: Resolvable[User],
        resolve_user_token: ResolvableSingular[User] | None = None,
    ) -> User | Tuple[User, ...]:
        """See if the token user can view another user.

        Resolve the user and verify that is not deleted.
        """

        user = self.token_user_or(resolve_user).check_not_deleted(410)
        user_token = self.token_user_or(resolve_user_token)

        # NOTE: When `GET` method, if the user is public, return. Otherwise
        #       always check for a token and check the token uuid.
        def check_one(user: User) -> User:
            match self.method:
                case _ if not user.public:
                    if self.token.uuid != user.uuid:
                        detail = dict(
                            uuid_user_token=user_token.uuid,
                            uuid_user=user.uuid,
                            msg="Cannot access private user.",
                        )
                        raise HTTPException(403, detail=detail)
                    return user
                case H.GET:
                    return user
                case H.POST | H.PATCH | H.PUT | H.DELETE:
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

        match (User.resolve(self.session, resolve_user)):
            case tuple() as users:
                return tuple(map(check_one, users))
            case User():
                return check_one(user)
            case _:
                raise HTTPException(405)

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
                            uuid_user=token_user.uuid,
                            uuid_collection=collection.uuid,
                            msg="Cannot modify collection.",
                        )

                        # Not sure how this happens on occasion.
                        if collection.id_user is None:
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

    # def check_document(
    #     self,
    #     user: User,
    #     document: Document,
    #     level: Level,
    #     exclude_deleted: bool = True,
    # ) -> Document:
    #     user.check_can_access_document(document, level)
    #     if exclude_deleted:
    #         document = document.check_not_deleted(410)
    #     return document
    #
    # ----------------------------------------------------------------------- #
    @overload
    def edit(
        self,
        resolve_edit: ResolvableSingular[Edit],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
    ) -> Edit: ...

    @overload
    def edit(
        self,
        resolve_edit: ResolvableMultiple[Edit],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
    ) -> Tuple[Edit, ...]: ...

    def edit(
        self,
        resolve_edit: Resolvable[Edit],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
    ) -> Edit | Tuple[Edit, ...]:
        match (resolved := Edit.resolve(self.session, resolve_edit)):
            case Edit() as edit:
                documents = edit.document
            case tuple() as edits:
                documents = tuple(edit.document for edit in edits)
            case _:
                raise ValueError()

        _ = self.document(
            documents,
            exclude_deleted=exclude_deleted,
            resolve_user_token=resolve_user_token,
        )
        return resolved

    # ----------------------------------------------------------------------- #
    # grants

    def grant_user(
        self,
        resolve_user: ResolvableSingular[User],
        resolve_documents: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular | None = None,
        level: Level | None = None,
    ) -> Tuple[User, Tuple[Document, ...]]:
        """When inspecting the user, one must authenticate as the user."""

        level = level if level is not None else self.level
        user_token = self.token_user_or(resolve_user_token)
        user = self.user(resolve_user, resolve_user_token=user_token)
        if user.uuid != user_token:
            raise HTTPException(
                403,
                detail=dict(
                    uuid_user_token=user.uuid,
                    uuid_user=user_token.uuid,
                    msg="User can only access own grants.",
                ),
            )

        # User can read, request, and remove all of their invitations.
        match self.method:
            # When posting, user may request only for documents that are
            # public, and when deleting
            case H.DELETE | H.POST | H.GET:
                level = Level.view
            case _:
                raise HTTPException(405)

        documents = self.document(
            resolve_documents,
            exclude_deleted=exclude_deleted,
            resolve_user_token=user_token,
            level=level,
        )
        return user, documents

    def grant_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_users: ResolvableMultiple[User],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular | None = None,
        level: Level | None = None,
    ) -> Tuple[Document, Tuple[User, ...]]:
        """When inspecting the user, one must authenticate as the user."""

        level = level if level is not None else self.level
        user_token = self.token_user_or(resolve_user_token)
        document = self.document(
            resolve_document,
            resolve_user_token=user_token,
            exclude_deleted=exclude_deleted,
            level=Level.own,
        )
        users = self.user(resolve_users)

        match self.method:
            case H.GET | H.POST | H.DELETE:
                return document, users
            case _:
                raise HTTPException(405)

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

    def assignment(
        self,
        source: Document | Collection,
        resolve_target: ResolvableMultiple[Collection] | ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
    ) -> AccessAssignmentResult:
        kwargs: Dict[str, Any] = dict(
            exclude_deleted=exclude_deleted,
            resolve_user_token=resolve_user_token,
            level=level,
        )
        match [source, resolve_target]:
            case [Document() as document, set() | tuple() as targets]:
                return self.assignment_document(document, targets, **kwargs)
            case [Collection() as collection, set() | tuple() as targets]:
                return self.assignment_collection(collection, targets, **kwargs)
            case _ as bad:
                raise ValueError(f"Unexpected source `{bad}`.")
