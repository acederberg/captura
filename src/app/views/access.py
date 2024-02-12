import functools
import inspect
from http import HTTPMethod
from typing import (
    Annotated,
    Any,
    Callable,
    Concatenate,
    Dict,
    Generic,
    List,
    Literal,
    ParamSpec,
    Sequence,
    Set,
    Tuple,
    TypeAlias,
    TypeVar,
    overload,
)

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
from app.views.base import (
    BaseController,
    Data,
    KindData,
    ResolvedAssignmentCollection,
    ResolvedAssignmentDocument,
    ResolvedCollection,
    ResolvedDocument,
    ResolvedEdit,
    ResolvedGrantDocument,
    ResolvedGrantUser,
    WithForceController,
)
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
        *,
        return_data: Literal[False] = False,
    ) -> Tuple[User, ...]: ...

    @overload
    def user(
        self,
        resolve_user: ResolvableSingular[User],
        resolve_user_token: ResolvableSingular[User] | None = None,
        *,
        return_data: Literal[False] = False,
    ) -> User: ...

    @overload
    def user(
        self,
        resolve_user: Resolvable[User],
        resolve_user_token: ResolvableSingular[User] | None = None,
        *,
        return_data: Literal[True] = True,
    ) -> Data: ...

    def user(
        self,
        resolve_user: Resolvable[User],
        resolve_user_token: ResolvableSingular[User] | None = None,
        *,
        return_data: bool = False,
    ) -> User | Tuple[User, ...] | Data:
        """See if the token user can view another user.

        Resolve the user and verify that is not deleted.
        """

        user_token = self.token_user_or(resolve_user_token)

        # NOTE: When `GET` method, if the user is public, return. Otherwise
        #       always check for a token and check the token uuid.
        def check_one(user: User) -> User:
            user.check_not_deleted()
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
                res = tuple(map(check_one, users))
            case User() as user:
                res = check_one(user)
            case _:
                raise HTTPException(405)

        if return_data:
            return Data(
                data=dict(user=res, kind="user"),  # type: ignore
                token_user=user_token,
            )
        return res

    # ----------------------------------------------------------------------- #
    # Collection

    @overload
    def collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        return_data: Literal[False] = False,
    ) -> Collection: ...

    @overload
    def collection(
        self,
        resolve_collection: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        return_data: Literal[False] = False,
    ) -> Tuple[Collection, ...]: ...

    @overload
    def collection(
        self,
        resolve_collection: Resolvable[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        return_data: Literal[True] = True,
    ) -> Data: ...

    def collection(
        self,
        resolve_collection: Resolvable[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        return_data: bool = False,
    ) -> Collection | Tuple[Collection, ...] | Data:

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
                res = check_one(collections)
            case tuple():
                res = tuple(map(check_one, collections))
            case _ as bad:
                raise ValueError(
                    "`collections must be a `Collection` or `tuple` of "
                    f"`Collection`s (got `{type(bad)}`)."
                )

        if return_data:
            return Data(
                data=ResolvedCollection(collection=res, kind="collection"),
                token_user=token_user,
            )
        return res

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
        return_data: Literal[False] = False,
    ) -> Document: ...

    @overload
    def document(
        self,
        resolve_document: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
        return_data: Literal[False] = False,
    ) -> Tuple[Document, ...]: ...

    @overload
    def document(
        self,
        resolve_document: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
        return_data: Literal[True] = True,
    ) -> Data: ...

    def document(
        self,
        resolve_document: Resolvable[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
        return_data: bool = False,
    ) -> Document | Tuple[Document, ...] | Data:

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
                res = tuple(map(check_one, documents))
            case Document():
                res = check_one(documents)
            case _ as bad:
                msg = f"Unexpected input of type `{type(bad)}`."
                raise ValueError(msg)

        if return_data:
            return Data(
                data=ResolvedDocument(document=res, kind="document"),
                token_user=token_user,
            )
        return res

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
        return_data: Literal[False] = False,
    ) -> Edit: ...

    @overload
    def edit(
        self,
        resolve_edit: ResolvableMultiple[Edit],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        return_data: Literal[False] = False,
    ) -> Tuple[Edit, ...]: ...

    @overload
    def edit(
        self,
        resolve_edit: ResolvableMultiple[Edit],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        return_data: Literal[True] = True,
    ) -> Data: ...

    def edit(
        self,
        resolve_edit: Resolvable[Edit],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        return_data: bool = False,
    ) -> Edit | Tuple[Edit, ...] | Data:
        user_token = self.token_user_or(resolve_user_token)
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
            return_data=False,
        )
        if return_data:
            return Data(
                data=ResolvedEdit(
                    edit=resolved,
                    kind="edit",
                ),
                token_user=user_token,
            )

        return resolved

    # ----------------------------------------------------------------------- #
    # grants
    @overload
    def grant_user(
        self,
        resolve_user: ResolvableSingular[User],
        resolve_documents: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular | None = None,
        level: Level | None = None,
        return_data: Literal[False] = False,
    ) -> Tuple[User, Tuple[Document, ...]]: ...

    @overload
    def grant_user(
        self,
        resolve_user: ResolvableSingular[User],
        resolve_documents: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular | None = None,
        level: Level | None = None,
        return_data: Literal[True] = True,
    ) -> Data: ...

    def grant_user(
        self,
        resolve_user: ResolvableSingular[User],
        resolve_documents: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular | None = None,
        level: Level | None = None,
        return_data: bool = False,
    ) -> Tuple[User, Tuple[Document, ...]] | Data:
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

        if return_data:
            return Data(
                data=ResolvedGrantUser(
                    documents=documents,
                    user=user,
                    kind="grant_user",
                ),
                token_user=user_token,
            )
        return user, documents

    @overload
    def grant_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_users: ResolvableMultiple[User],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular | None = None,
        level: Level | None = None,
        return_data: Literal[False] = False,
    ) -> Tuple[Document, Tuple[User, ...]]: ...

    @overload
    def grant_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_users: ResolvableMultiple[User],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular | None = None,
        level: Level | None = None,
        return_data: Literal[True] = True,
    ) -> Data: ...

    def grant_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_users: ResolvableMultiple[User],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular | None = None,
        level: Level | None = None,
        return_data: bool = False,
    ) -> Tuple[Document, Tuple[User, ...]] | Data:
        """For document owners only."""

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
            case H.GET | H.POST | H.DELETE | H.PUT:
                if return_data:
                    return Data(
                        data=ResolvedGrantDocument(
                            document=document, users=users, kind="grant_document"
                        ),
                        token_user=user_token,
                    )
                return document, users
            case _:
                raise HTTPException(405)

    # ----------------------------------------------------------------------- #
    # Assignments

    @overload
    def assignment_collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        resolve_documents: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
        return_data: Literal[False] = False,
    ) -> Tuple[Collection, Tuple[Document, ...]]: ...

    @overload
    def assignment_collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        resolve_documents: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
        return_data: Literal[True] = True,
    ) -> Data: ...

    def assignment_collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        resolve_documents: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
        return_data: bool = False,
    ) -> Tuple[Collection, Tuple[Document, ...]] | Data:

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
        if return_data:
            return Data(
                data=ResolvedAssignmentCollection(
                    kind="assignment_collection",
                    collection=collection,
                    documents=documents,
                ),
                token_user=token_user,
            )
        return collection, documents

    @overload
    def assignment_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_collections: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
        return_data: Literal[False] = False,
    ) -> Tuple[Document, Tuple[Collection, ...]]: ...

    @overload
    def assignment_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_collections: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
        return_data: Literal[True] = True,
    ) -> Data: ...

    def assignment_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_collections: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
        return_data: bool = False,
    ) -> Tuple[Document, Tuple[Collection, ...]] | Data:

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
        if return_data:
            return Data(
                data=ResolvedAssignmentDocument(
                    kind="assignment_document",
                    document=document,
                    collections=collections,
                ),
                token_user=token_user,
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
    ) -> AccessAssignmentResult | Data:
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

    def __call__(
        self,
        data: Data,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: Level | None = None,
    ) -> Data:

        # match data.__ne__:
        #     case Document | Document
        #     case Collection | (Collection(), *_):
        #         ...
        return data


T_WithAccess = TypeVar("T_WithAccess")
P_WithAccess = ParamSpec("P_WithAccess")
CallableAccess: TypeAlias = Callable[
    Concatenate[Access, P_WithAccess],
    T_WithAccess,
]
CallableWithAccess: TypeAlias = Callable[
    Concatenate["WithAccess", P_WithAccess],
    T_WithAccess,
]


class with_access:
    _fn_access: CallableAccess | None
    fn: CallableWithAccess | None

    def __init__(self, fn_access: CallableAccess | None = None):
        self._fn_access = fn_access
        self.fn = None

    # def inspect_signature(self, fn: CallableWithAccess, fn_access: CallableAccess):
    #     sig = inspect.signature(fn)
    #     sig_access = inspect.signature(fn_access)
    #     if (sig.parameters) != (sig_access.parameters):
    #         raise ValueError(
    #             f"Invalid parameters For `{fn.__name__}`.\n"
    #             f"Expected `{sig_access}`.\n"
    #             f"Recieved `{sig}`."
    #         )

    def fn_access(self) -> CallableAccess:
        if self._fn_access is not None:
            return self._fn_access
        elif (fn := self.fn) is None:
            raise AttributeError("`fn` must be set.")

        res = getattr(Access, name := fn.__name__, None)
        if res is None:
            raise ValueError(f"No such method `{name}` of `Access`.")
        elif not callable(res):
            raise ValueError(
                f"Attribute `{name}` must be callable and match the "
                f"signature of `Access.{name}`."
            )

        return res

    def __call__(self, fn: CallableWithAccess) -> CallableWithAccess:
        """Chain together :param:`method` with the appropriate access method.

        The intended result is to avoid having to write this so often:

        .. code:: python

            def doit(
                resolvable_collection: ResolvableSingular[Collection],
                resolvable_documents: ResolvableMultiple[Document],
            ):
                access = Access(session, token, method)
                collection, documents = access.assignment(
                    resolvable_collection,
                    resolvable_documents
                )
                delete = access.then(Delete)
                event = delete(collection, documents)

        when the access controller was not included in deleted. This MUST be
        used in combination with `WithAccess` so that the access controller is
        available from `self`.

        :param fn: Callable to decorate.
        """

        self.fn = fn
        fn_access: CallableAccess = self.fn_access()

        @functools.wraps(fn)
        def wrapper(
            self: WithAccess,
            *args: P_WithAccess.args,
            **kwargs: P_WithAccess.kwargs,
        ):

            # NOTE: `data` should be resolved resolvables. This is why the
            #       signatures must match, and further, the output and input
            #       of all controller methods will resolavble data and resolved
            #       outputs.
            args = fn_access(self.access, *args, **kwargs)
            return fn(*args, **kwargs)

        return wrapper


class WithAccessMeta(type):

    def __new__(cls, name, bases, namespace):
        for kind in KindData:
            fn_name = kind.name
            fn = namespace.get(fn_name, None)
            match fn:
                case with_access() | None:
                    pass
                case _:
                    namespace[fn_name] = with_access()(fn)

        T = super().__new__(cls, name, bases, namespace)
        return T


class WithAccess(WithForceController, metaclass=WithAccessMeta):

    access: Access

    def __init__(
        self,
        session: Session,
        token: Token | Dict[str, Any] | None,
        method: HTTPMethod | str,
        *,
        detail: str,
        api_origin: str,
        force: bool = True,
        access: Access | None = None,
    ):
        super().__init__(
            session,
            token,
            method,
            detail=detail,
            api_origin=api_origin,
            force=force,
        )
        self.access = access if access is not None else self.then(Access)
