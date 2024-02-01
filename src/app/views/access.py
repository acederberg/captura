from http import HTTPMethod
from typing import Annotated, List, Sequence, Set, Tuple, TypeAlias, overload

from app.depends import DependsToken
from app.models import (
    AssocCollectionDocument,
    AssocUserDocument,
    Collection,
    Document,
    Level,
    User,
)
from app.views import args
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

CollectionItemVerifyAccess = (
    args.PathUUIDCollection
    | args.QueryUUIDCollection
    | Collection
    | Sequence[Collection]
)
DocumentItemVerifyAccess = (
    args.PathUUIDDocument | args.QueryUUIDDocument | Document | List[Document]
)


class Access:
    token: DependsToken | None
    session: Session
    method: HTTPMethod

    # exclude_public: bool = True
    # exclude_deleted: bool = True

    # NOTE: Will be constructed by depends. Do not add fn parameters here.
    def __init__(
        self,
        session: Session,
        token: DependsToken | None,
        *,
        method: HTTPMethod = HTTPMethod.POST,
        # exclude_deleted: bool = True,
    ):
        self.session = session
        self.token = token
        self.method = method
        # self.exclude_public = exclude_public
        # self.exclude_deleted = exclude_deleted

    # ----------------------------------------------------------------------- #
    # User

    def user(
        self,
        uuid_user: args.PathUUIDUser | User | None = None,
    ) -> User:

        user: User
        match uuid_user:
            case User():
                user = uuid_user
            case None if self.token is not None:
                user = User.if_exists(self.session, self.token["uuid"])
            case str():
                user = User.if_exists(self.session, uuid_user, 404)
            case None | _ as bad_or_missing:
                if bad_or_missing is None:
                    raise ValueError(
                        "Argument `uuid_user` must be provided when `Access` "
                        "instance does not specify a token."
                    )
                raise ValueError(f"Invalid argument `{bad_or_missing}`.")

        user.check_not_deleted()

        # NOTE: When `GET` method, if the user is public, return. Otherwise
        #       always check for a token and check the token uuid.
        if self.method == HTTPMethod.GET and user.public:
            return user

        if self.token is None:
            msg = "User must login to access."
            raise HTTPException(401, detail=dict(msg=msg))
        elif user.uuid != self.token["uuid"]:
            detail = dict(
                uuid_user=uuid_user,
                uuid_user_token=self.token["uuid"],
                msg="Cannot modify other user.",
            )
            raise HTTPException(403, detail)
        return user

    # ----------------------------------------------------------------------- #
    # Collection

    @overload
    def collection(
        self,
        uuid_collection: args.PathUUIDCollection | Collection,
        *,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Collection]: ...

    @overload
    def collection(
        self,
        uuid_collection: args.QueryUUIDCollection | Sequence[Collection],
        *,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Tuple[Collection, ...]]: ...

    def collection(
        self,
        uuid_collection: CollectionItemVerifyAccess,
        *,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Collection] | Tuple[User, Tuple[Collection, ...]]:
        user = User.if_exists(self.session, self.token["uuid"])
        user.check_not_deleted(410)

        def check_one(collection: Collection) -> Collection:
            # NOTE: `exclude_deleted` should only be ``True`` when a force
            #       deletion is occuring.
            if exclude_deleted:
                collection = collection.check_not_deleted(410)
            user.check_can_access_collection(collection)
            return collection

        if isinstance(uuid_collection, str):
            collections = Collection.if_exists(self.session, uuid_collection)
            collections = check_one(collections)
            return user, collections
        elif isinstance(uuid_collection, set):
            collections = Collection.if_many(
                self.session,
                uuid_collection,
                check_one,
            )
            return user, collections
        elif isinstance(uuid_collection, Collection):
            return user, check_one(uuid_collection)
        elif isinstance(uuid_collection, list):
            return user, tuple(check_one(item) for item in uuid_collection)
        else:
            raise ValueError()

    # ----------------------------------------------------------------------- #
    # Documents

    @overload
    def document(
        self,
        uuid_document: args.PathUUIDDocument | Document,
        *,
        level: Level,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Document]: ...

    @overload
    def document(
        self,
        uuid_document: args.QueryUUIDDocument | List[Document],
        *,
        level: Level,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Tuple[Document, ...]]: ...

    def document(
        self,
        uuid_document: DocumentItemVerifyAccess,
        *,
        level: Level,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Document] | Tuple[User, Tuple[Document, ...]]:
        if isinstance(self.token, dict):
            user = User.if_exists(self.session, self.token["uuid"], 403)
        else:
            user = self.token

        user = user.check_not_deleted(410)

        def check_one(document: Document) -> Document:
            # NOTE: Exclude deleted is only required for force deletion.
            if exclude_deleted:
                document = document.check_not_deleted(410)
            user.check_can_access_document(document, level)
            return document

        if isinstance(uuid_document, str):
            documents = Document.if_exists(self.session, uuid_document)
            return user, check_one(documents)
        elif isinstance(uuid_document, set):
            documents = Document.if_many(self.session, uuid_document, check_one)
            return user, documents
        elif isinstance(uuid_document, Document):
            return user, check_one(uuid_document)
        elif isinstance(uuid_document, list):
            return user, tuple(check_one(item) for item in uuid_document)
        else:
            msg = f"Unexpected input of type `{type(uuid_document)}`."
            raise ValueError(msg)

    # ----------------------------------------------------------------------- #
    # Assignments

    def assignment(
        self,
        uuid_collection: Set[str],
        *,
        uuid_document: Set[str],
        level: Level,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Tuple[Document, ...], Tuple[Collection, ...]]:
        user, collections = self.collection(
            uuid_collection,
            exclude_deleted=exclude_deleted,
        )
        user, documents = self.document(
            uuid_document,
            level=level,
            exclude_deleted=exclude_deleted,
        )

        return user, documents, collections


# def create_access(
#     session: DependsSessionMaker,
#     token: DependsToken,
# ) -> Access:
#     return Access(session, token)
#
#
# DependsAccess: TypeAlias = Annotated[Access, Depends(create_access)]
