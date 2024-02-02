from http import HTTPMethod
from typing import Annotated, List, Sequence, Set, Tuple, TypeAlias, overload

from app.depends import DependsToken
from app.models import (
    AssocCollectionDocument,
    AssocUserDocument,
    ChildrenAssignment,
    Collection,
    Document,
    Level,
    Resolvable,
    ResolvableMultiple,
    ResolvableSingular,
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

    def get_user(
        self,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> User:
        resolve_final: ResolvableSingular[User]
        match [self.token, resolve_user]:
            case [None, None]:
                raise HTTPException(401, detail="No user to resolve.")
            case [None, matched] if matched is not None:
                resolve_final = matched
            case [matched, None] if matched is not None:
                resolve_final = matched["uuid"]
            case _:
                raise ValueError("Inconcievable!")

        user = User.resolve(self.session, resolve_final)
        user = user.check_not_deleted(410)

        return user

    def user(
        self,
        uuid_user: ResolvableSingular[User] | None = None,
    ) -> User:

        user = self.get_user(uuid_user)
        # NOTE: When `GET` method, if the user is public, return. Otherwise
        #       always check for a token and check the token uuid.
        if self.method == HTTPMethod.GET:
            if not user.public:
                detail = dict(uuid_user=user.uuid, msg="User is not public.")
                raise HTTPException(403, detail=detail)
            else:
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
        uuid_collection: ResolvableSingular[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> Tuple[User, Collection]: ...

    @overload
    def collection(
        self,
        uuid_collection: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> Tuple[User, Tuple[Collection, ...]]: ...

    def collection(
        self,
        uuid_collection: Resolvable[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> Tuple[User, Collection] | Tuple[User, Tuple[Collection, ...]]:

        user = self.get_user(resolve_user)

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
        uuid_document: ResolvableSingular[Document],
        *,
        level: Level,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> Tuple[User, Document]: ...

    @overload
    def document(
        self,
        uuid_document: ResolvableMultiple[Document],
        *,
        level: Level,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> Tuple[User, Tuple[Document, ...]]: ...

    def document(
        self,
        uuid_document: Resolvable[Document],
        *,
        level: Level,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> Tuple[User, Document] | Tuple[User, Tuple[Document, ...]]:

        user = self.get_user(resolve_user)

        def check_one(document: Document) -> Document:
            # NOTE: Exclude deleted is only required for force deletion.
            if exclude_deleted:
                print(document)
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

    def assignment_collection(
        self,
        resolve_source: ResolvableSingular[Collection],
        *,
        resolve_target: ResolvableMultiple[Document],
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> Tuple[User, Collection, Tuple[Document, ...]]:

        user = self.get_user(resolve_user)
        user, collection = self.collection(
            resolve_source,
            exclude_deleted=exclude_deleted,
            resolve_user=user,
        )
        user, documents = self.document(
            resolve_target,
            level=Level.view,
            exclude_deleted=exclude_deleted,
            resolve_user=user,
        )
        return user, collection, documents

    def assignment_document(
        self,
        resolve_source: ResolvableSingular[Document],
        *,
        resolve_target: ResolvableMultiple[Collection],
        level: Level,
        exclude_deleted: bool = True,
        resolve_user: ResolvableSingular[User] | None = None,
    ) -> Tuple[User, Document, Tuple[Collection, ...]]:

        user = self.get_user(resolve_user)
        user, document = self.document(
            resolve_source,
            level=level,
            exclude_deleted=exclude_deleted,
            resolve_user=user,
        )
        user, collections = self.collection(
            resolve_target,
            exclude_deleted=exclude_deleted,
            resolve_user=user,
        )

        return user, document, collections

    # @overload
    # def assignment(
    #     self,
    #     source_kind: ChildrenAssignment,
    #     resolve_source: ResolvableSingular[Collection],
    #     *,
    #     resolve_target: ResolvableMultiple[Document],
    #     level: Level,
    #     exclude_deleted: bool = True,
    #     resolve_user: ResolvableSingular[User] | None = None,
    # ) -> Tuple[User, Tuple[Document, ...], Collection]: ...
    #
    # @overload
    # def assignment(
    #     self,
    #     source_kind: ChildrenAssignment,
    #     resolve_source: ResolvableSingular[Document],
    #     *,
    #     resolve_target: ResolvableMultiple[Collection],
    #     level: Level,
    #     exclude_deleted: bool = True,
    #     resolve_user: ResolvableSingular[User] | None = None,
    # ) -> Tuple[User, Document, Tuple[Collection, ...]]: ...
    #
    # def assignment(
    #     self,
    #     source_kind: ChildrenAssignment,
    #     resolve_source: ResolvableSingular[Collection] | ResolvableSingular[Document],
    #     *,
    #     resolve_target: ResolvableMultiple[Document] | ResolvableMultiple[Collection],
    #     level: Level,
    #     exclude_deleted: bool = True,
    #     resolve_user: ResolvableSingular[User] | None = None,
    # ) -> (
    #     Tuple[User, Document, Tuple[Collection, ...]]
    #     | Tuple[User, Tuple[Document, ...], Collection]
    # ):
    #
    #     # uuid_document: Resolvable[Document],
    #     # *,
    #     # level: Level,
    #     # exclude_deleted: bool = True,
    #     # resolve_user: ResolvableSingular[User] | None = None,
    #     user = self.get_user(resolve_user)
    #     match source_kind:
    #         case ChildrenAssignment.documents:
    #             user, document = self.document(  # type: ignore
    #                 resolve_source,
    #                 level,
    #                 exclude_deleted=exclude_deleted,
    #                 user=user,
    #             )
    #             user, collection = self.collection(  # type: ignore
    #                 resolve_target,
    #                 exclude_deleted=exclude_deleted,
    #                 user=user,
    #             )
    #             return user, document, collection  # type: ignore
    #
    #         case Collection():
    #             user, collection = self.collection(  # type: ignore
    #                 resolve_source, exclude_deleted=exclude_deleted, user=user
    #             )
    #             user, document = self.document(  # type: ignore
    #                 resolve_target,
    #                 level=level,
    #                 exclude_deleted=exclude_deleted,
    #                 user=user,
    #             )
    #             return user, document, collection
    #         case _:
    #             raise ValueError("Inconcievable!")
    #


# def create_access(
#     session: DependsSessionMaker,
#     token: DependsToken,
# ) -> Access:
#     return Access(session, token)
#
#
# DependsAccess: TypeAlias = Annotated[Access, Depends(create_access)]
