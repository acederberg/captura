# =========================================================================== #
import abc
import functools
from http import HTTPMethod
from typing import (
    Any,
    Callable,
    Concatenate,
    Dict,
    Literal,
    ParamSpec,
    Tuple,
    Type,
    TypeVar,
    overload,
)

from fastapi import HTTPException
from sqlalchemy import false, select
from sqlalchemy.orm import Session

# --------------------------------------------------------------------------- #
from captura import __version__
from captura.auth import Token
from captura.controllers.base import (
    BaseController,
    Data,
    DataResolvedAssignment,
    DataResolvedGrant,
    KindData,
    ResolvedAssignmentCollection,
    ResolvedAssignmentDocument,
    ResolvedCollection,
    ResolvedDocument,
    ResolvedEvent,
    ResolvedGrantDocument,
    ResolvedGrantUser,
    ResolvedObjectEvents,
    ResolvedUser,
    T_Data,
)
from captura.err import (
    ErrAccessCollection,
    ErrAccessDocumentCannotRejectOwner,
    ErrAccessUser,
    ErrUpdateGrantPendingFrom,
)
from captura.fields import PendingFrom, Singular
from captura.models import (
    Base,
    Collection,
    Document,
    Event,
    Grant,
    KindObject,
    Level,
    Resolvable,
    ResolvableLevel,
    ResolvableMultiple,
    ResolvableSingular,
    T_Resolvable,
    Tables,
    User,
)
from captura.schemas import EventParams, EventSearchSchema, mwargs

H = HTTPMethod
AccessAssignmentResult = (
    Tuple[Collection, Tuple[Document, ...]] | Tuple[Document, Tuple[Collection, ...]]
)


class Access(BaseController):
    def __call__(
        self,
        kind_data: KindData,
        resolvable: ResolvableSingular,
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        return_data: bool = False,
        **kwargs,
    ) -> Data:
        if (method := getattr(self, kind_data.name, None)) is None:
            raise ValueError(f"No such method `{kind_data.name}` of `Access`.")
        return method(
            resolvable,
            resolve_user_token=resolve_user_token,
            exclude_deleted=exclude_deleted,
            return_data=return_data,
            **kwargs,
        )

    # ----------------------------------------------------------------------- #
    # Events

    # NOTE: Order of overloads matters.
    @overload
    def event(
        self,
        resolvable_uuid: Resolvable[Event],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        return_data: Literal[True] = True,
    ) -> Data[ResolvedEvent]: ...

    @overload
    def event(
        self,
        resolvable_uuid: ResolvableMultiple[Event],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        return_data: Literal[False] = False,
    ) -> Tuple[Event, ...]: ...

    @overload
    def event(
        self,
        resolvable_uuid: ResolvableSingular[Event],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        return_data: Literal[False] = False,
    ) -> Event: ...

    def event(
        self,
        resolvable_uuid: Resolvable[Event],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        return_data: bool = False,
    ) -> Event | Tuple[Event, ...] | Data[ResolvedEvent]:
        session = self.session
        token_user = self.token_user_or(resolve_user_token)
        events = Event.resolve(session, resolvable_uuid)

        def check_one(event: Event) -> Event:
            token_user.check_can_access_event(event)
            if exclude_deleted:
                event.check_not_deleted()
            return event

        res: Tuple[Event, ...] | Event
        match events:
            case tuple() as items:
                res = tuple(map(check_one, items))
            case Event() as item:
                res = check_one(item)
                if not return_data:
                    return res
            case bad:
                raise ValueError(f"Invalid input `{bad}`.")

        if return_data:
            return mwargs(
                Data[ResolvedEvent],
                data=mwargs(ResolvedEvent, events=events, token_user=token_user),
            )
        return res

    def d_event(
        self,
        resolvable_uuid: Resolvable[Event],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
    ) -> Data[ResolvedEvent]:
        return self.event(
            resolvable_uuid,
            resolve_user_token=resolve_user_token,
            exclude_deleted=exclude_deleted,
            return_data=True,
        )

    @overload
    def object_events(  # type: ignore[overload-overlap]
        self,
        object_resolvable: ResolvableSingular[T_Resolvable],
        object_kind: KindObject,
        param: EventSearchSchema | EventParams | None = None,
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        return_data: Literal[True] = True,
    ) -> Data[ResolvedObjectEvents]: ...

    @overload
    def object_events(
        self,
        object_resolvable: ResolvableSingular[T_Resolvable],
        object_kind: KindObject,
        param: EventSearchSchema | EventParams | None = None,
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        return_data: Literal[False] = False,
    ) -> Tuple[T_Resolvable, Tuple[Event, ...]]: ...

    def object_events(
        self,
        object_resolvable: ResolvableSingular[T_Resolvable],
        object_kind: KindObject,
        param: EventSearchSchema | EventParams | None = None,
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        return_data: bool = False,
    ) -> Data[ResolvedObjectEvents] | Tuple[T_Resolvable, Tuple[Event, ...]]:
        # NOTE: Resolved.
        resolve_user_token = self.token_user_or(resolve_user_token)
        T_Mapped: Type[Base]  # [T_Resolvable]
        T_Mapped = Tables[Singular(object_kind.name).name].value
        object_: T_Resolvable = T_Mapped.resolve(  # type: ignore
            self.session,
            object_resolvable,
        )

        # NOTE: Check access to the object.
        _ = self(
            KindData[object_kind.name],
            object_,
            resolve_user_token=resolve_user_token,
            exclude_deleted=exclude_deleted,
            return_data=False,
        )

        # Find events.
        if param is not None:
            match param:
                case EventParams():
                    exclude = {"root"}
                case EventSearchSchema():
                    exclude = set()

            search = param.model_dump(exclude=exclude)
        else:
            search = dict()

        q_event = Event.q_select_search(**search)
        events = tuple(self.session.execute(q_event).scalars())

        if return_data:
            return mwargs(
                Data[ResolvedObjectEvents],
                data=mwargs(
                    ResolvedObjectEvents,
                    obj=object_,
                    kind_obj=object_kind,
                    events=events,
                ),
            )

        return object_, events

    def d_object_events(
        self,
        object_resolvable: ResolvableSingular[T_Resolvable],
        object_kind: KindObject,
        param: EventSearchSchema | EventParams | None = None,
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
    ) -> Data[ResolvedObjectEvents]:
        return self.object_events(
            object_resolvable,
            object_kind,
            param,
            resolve_user_token=resolve_user_token,
            exclude_deleted=exclude_deleted,
            return_data=True,
        )

    # ----------------------------------------------------------------------- #
    # User

    @overload
    def user(
        self,
        resolve_user: Resolvable[User],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        exclude_public: bool = False,
        return_data: Literal[True] = True,
    ) -> Data[ResolvedUser]: ...

    @overload
    def user(
        self,
        resolve_user: ResolvableMultiple[User],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        exclude_public: bool = False,
        return_data: Literal[False] = False,
    ) -> Tuple[User, ...]: ...

    @overload
    def user(
        self,
        resolve_user: ResolvableSingular[User],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        exclude_public: bool = False,
        return_data: Literal[False] = False,
    ) -> User: ...

    def user(  # type: ignore
        self,
        resolve_user: Resolvable[User],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        exclude_public: bool = False,
        return_data: bool = False,
    ) -> User | Tuple[User, ...] | Data[ResolvedUser]:
        """See if the token user can view another user.

        Resolve the user and verify that is not deleted.
        """

        user_token = self.token_user_or(resolve_user_token)
        users: Tuple[User, ...]
        match res := User.resolve(self.session, resolve_user):
            case tuple() as users:
                users = tuple(
                    self._user(
                        user,
                        user_token,
                        exclude_public=exclude_public,
                        exclude_deleted=exclude_deleted,
                    )
                    for user in users
                )
            case User() as user:
                user = self._user(
                    user,
                    user_token,
                    exclude_deleted=exclude_deleted,
                    exclude_public=exclude_public,
                )
                if not return_data:
                    return user
                users = (user,)
            case _:
                raise HTTPException(405)

        if return_data:
            return Data(
                data=ResolvedUser.model_validate(dict(users=users, kind="user")),  # type: ignore
                token_user=user_token,
                event=None,
            )
        return res

    # NOTE: When `GET` method, if the user is public, return. Otherwise
    #       always check for a token and check the token uuid.
    def _user(
        self,
        user: User,
        user_token: User,
        *,
        exclude_public: bool = False,
        exclude_deleted: bool = True,
        msg_name: (
            Literal[
                "_msg_private",
                "_msg_modify",
                "_msg_only_self",
            ]
            | None
        ) = None,
    ) -> User:
        """
        :param exclude_public: When ``True``, will exclude checking if user is
            public or not in the ``get`` case.
        """
        # if user.admin:
        #     return user
        if exclude_deleted:
            user.check_not_deleted()

        match self.method:
            # case _ if not user.public:
            #     return user
            case H.GET if not exclude_public:
                if (
                    # not exclude_public
                    not user.public
                    and user_token.uuid != user.uuid
                ):
                    raise ErrAccessUser.httpexception(
                        msg_name or "_msg_private",
                        403,
                        uuid_user_token=user_token.uuid,
                        uuid_user=user.uuid,
                    )
                return user
            case H.POST | H.PATCH | H.PUT | H.DELETE | H.GET:
                if user.uuid != user_token.uuid:
                    if self.method == H.GET:
                        msg_name = "_msg_private"

                    raise ErrAccessUser.httpexception(
                        msg_name or "_msg_modify",
                        403,
                        uuid_user=user.uuid,
                        uuid_user_token=user_token.uuid,
                        # msg=msg_access_user,
                    )
                return user
            case _ as bad:
                raise ValueError(f"Cannot yet method `{bad}`.")

    # NOTE: Tried partials. Makes typing hell worse. Easier just to write out.
    #       Tried many other solutions, just do this for now. Should have used
    #       lang with actual overloading.
    def d_user(
        self,
        resolve_user: Resolvable[User],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_public: bool = False,
        exclude_deleted: bool = True,
    ) -> Data[ResolvedUser]:
        return self.user(
            resolve_user,
            resolve_user_token=resolve_user_token,
            return_data=True,
            exclude_deleted=exclude_deleted,
            exclude_public=exclude_public,
        )

    # ----------------------------------------------------------------------- #
    # Collection

    @overload
    def collection(  # type: ignore[overload-overlap]
        self,
        resolve_collection: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        return_data: Literal[False] = False,
        allow_public: bool = True,
    ) -> Tuple[Collection, ...]: ...

    @overload
    def collection(
        self,
        resolve_collection: Resolvable[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        return_data: Literal[True] = True,
        allow_public: bool = True,
    ) -> Data[ResolvedCollection]: ...

    @overload
    def collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        return_data: Literal[False] = False,
        allow_public: bool = True,
    ) -> Collection: ...

    def collection(
        self,
        resolve_collection: Resolvable[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        return_data: bool = False,
        allow_public: bool = True,
    ) -> Collection | Tuple[Collection, ...] | Data[ResolvedCollection]:
        # NOTE: `exclude_deleted` should only be ``True`` when a force
        #       deletion is occuring.
        def check_one(collection: Collection) -> Collection:
            if exclude_deleted:
                collection = collection.check_not_deleted()

            match self.method:
                case H.GET if allow_public:
                    if not collection.public and collection.id_user != token_user.id:
                        raise ErrAccessCollection.httpexception(
                            "_msg_private",
                            403,
                            uuid_user_token=token_user.uuid,
                            uuid_collection=collection.uuid,
                        )
                    return collection
                case H.GET | H.POST | H.DELETE | H.PUT | H.PATCH:
                    if token_user.id != collection.id_user:
                        raise ErrAccessCollection.httpexception(
                            "_msg_modify",
                            403,
                            uuid_user_token=token_user.uuid,
                            uuid_collection=collection.uuid,
                        )
                    return collection
                case _:
                    msg = f"Cannot handle HTTPMethod `{self.method}`."
                    raise ValueError(msg)

        token_user = self.token_user_or(resolve_user_token)

        collections: Tuple[Collection, ...]
        match res := Collection.resolve(self.session, resolve_collection):
            case Collection():
                _collection = check_one(res)
                if not return_data:
                    return _collection
                collections = (_collection,)
            case tuple():
                collections = tuple(map(check_one, res))
            case _ as bad:
                raise ValueError(
                    "`collections must be a `Collection` or `tuple` of "
                    f"`Collection`s (got `{type(bad)}`)."
                )

        if return_data:
            return mwargs(
                Data[ResolvedCollection],
                data=mwargs(
                    ResolvedCollection,
                    collections=collections,
                    kind="collection",
                ),
                token_user=token_user,
                event=None,
            )
        return res

    def d_collection(
        self,
        resolve_collection: Resolvable[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        allow_public: bool = True,
    ) -> Data[ResolvedCollection]:
        return self.collection(
            resolve_collection,
            exclude_deleted=exclude_deleted,
            resolve_user_token=resolve_user_token,
            allow_public=allow_public,
            return_data=True,
        )

    # ----------------------------------------------------------------------- #
    # Documents

    @overload
    def document(
        self,
        resolve_document: Resolvable[Document],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        return_data: Literal[True] = True,
        level: ResolvableLevel | None = None,
        grants: Dict[str, Grant] | None = None,
        grants_index: Literal["uuid_document", "uuid_user"] = "uuid_document",
        pending: bool = False,
        validate: bool = True,
        allow_public: bool = False,
        # pending_from: PendingFrom | None = None,
    ) -> Data[ResolvedDocument]: ...

    @overload
    def document(
        self,
        resolve_document: ResolvableSingular[Document],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        return_data: Literal[False] = False,
        level: ResolvableLevel | None = None,
        grants: Dict[str, Grant] | None = None,
        grants_index: Literal["uuid_document", "uuid_user"] = "uuid_document",
        pending: bool = False,
        validate: bool = True,
        allow_public: bool = False,
        # pending_from: PendingFrom | None = None,
    ) -> Document: ...

    @overload
    def document(
        self,
        resolve_document: ResolvableMultiple[Document],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        return_data: Literal[False] = False,
        level: ResolvableLevel | None = None,
        grants: Dict[str, Grant] | None = None,
        grants_index: Literal["uuid_document", "uuid_user"] = "uuid_document",
        pending: bool = False,
        validate: bool = True,
        allow_public: bool = False,
        # pending_from: PendingFrom | None = None,
    ) -> Tuple[Document, ...]: ...

    def document(
        self,
        resolve_document: Resolvable[Document],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        return_data: bool = False,
        level: ResolvableLevel | None = None,
        grants: Dict[str, Grant] | None = None,
        grants_index: Literal["uuid_document", "uuid_user"] = "uuid_document",
        pending: bool = False,
        validate: bool = True,
        allow_public: bool = False,
        # pending_from: PendingFrom | None = None,
    ) -> Document | Tuple[Document, ...] | Data[ResolvedDocument]:
        level = level if level is not None else self.level
        token_user = self.token_user_or(resolve_user_token)
        if grants is None:
            grants = dict()

        # NOTE: Exclude deleted is only required for force deletion. Deletedness
        #       exceeds access in terms of priority.
        def check_one(document: Document) -> Document:
            if exclude_deleted:
                document = document.check_not_deleted()
            if allow_public and document.public:
                return document
            else:
                token_user.check_can_access_document(
                    document,
                    level,
                    grants=grants,
                    grants_index=grants_index,
                    pending=pending,
                    exclude_deleted=exclude_deleted,
                    validate=validate,
                )
            return document

        documents: Tuple[Document, ...]
        match Document.resolve(self.session, resolve_document):
            case tuple() as documents:
                documents = tuple(map(check_one, documents))
            case Document() as document:
                _document = check_one(document)
                if not return_data:
                    return _document
                documents = (_document,)
            case _ as bad:
                msg = f"Unexpected input of type `{type(bad)}`."
                raise ValueError(msg)

        if return_data:
            return mwargs(
                Data[ResolvedDocument],
                data=ResolvedDocument.model_validate(
                    dict(
                        documents=documents,
                        kind="document",
                        token_user_grants=grants,
                    )
                ),
                token_user=token_user,
                event=None,
            )
        return documents

    def d_document(
        self,
        resolve_document: Resolvable[Document],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        level: ResolvableLevel | None = None,
        pending: bool = False,
        validate: bool = True,
        allow_public: bool = False,
        # pending_from: PendingFrom | None = None,
    ) -> Data[ResolvedDocument]:
        return self.document(
            resolve_document,
            exclude_deleted=exclude_deleted,
            resolve_user_token=resolve_user_token,
            level=level,
            return_data=True,
            pending=pending,
            validate=validate,
            allow_public=allow_public,
            # pending_from=pending_from,
        )

    # ----------------------------------------------------------------------- #
    # grants

    @overload
    def grant_user(  # type: ignore[overload-overlap]
        self,
        resolve_user: ResolvableSingular[User],
        resolve_documents: ResolvableMultiple[Document] | None,
        *,
        resolve_user_token: ResolvableSingular | None = None,
        exclude_deleted: bool = True,
        level: ResolvableLevel | None = None,
        return_data: Literal[False] = False,
        pending: bool = False,
        validate: bool = False,
        # pending_from: PendingFrom | None = None,
    ) -> Tuple[User, Tuple[Document, ...]]: ...

    @overload
    def grant_user(
        self,
        resolve_user: ResolvableSingular[User],
        resolve_documents: ResolvableMultiple[Document] | None,
        *,
        resolve_user_token: ResolvableSingular | None = None,
        exclude_deleted: bool = True,
        level: ResolvableLevel | None = None,
        return_data: Literal[True] = True,
        pending: bool = False,
        validate: bool = False,
        # pending_from: PendingFrom | None = None,
    ) -> Data[ResolvedGrantUser]: ...

    def grant_user(
        self,
        resolve_user: ResolvableSingular[User],
        resolve_documents: ResolvableMultiple[Document] | None,
        *,
        resolve_user_token: ResolvableSingular | None = None,
        exclude_deleted: bool = True,
        level: ResolvableLevel | None = None,
        return_data: bool = False,
        pending: bool = False,
        validate: bool = False,
        # pending_from: PendingFrom | None = None,
    ) -> Tuple[User, Tuple[Document, ...]] | Data[ResolvedGrantUser]:
        """When inspecting the user, one must authenticate as the user.

        About `PendingFrom`
        -----------------------------------------------------------------------

        Pending from would be nice to have up front (i.e. here) but its value
        only really matters when accepting grants, so the functionality exists
        in the corresponding method (with a similar name) in :class:`Update`.

        More or less, in the update case, the status of the documents would
        have to be checked when :attr:`method` is ``PATCH``.


        About Checking Document Permissions
        -----------------------------------------------------------------------

        Access is generally not required for the documents in
        ``resolve_documents``. However, it would still be useful to populate
        ``grants`` using ``self.document``. For this reason the parameter
        ``validate`` is added.
        """

        level = Level.resolve(level) if level is not None else self.level
        user_token = self.token_user_or(resolve_user_token)

        user = self._user(
            User.resolve(self.session, resolve_user),
            user_token,
            exclude_deleted=exclude_deleted,
            exclude_public=True,
            msg_name="_msg_only_self",
        )
        document_kwargs: Dict[str, Any] = dict(
            exclude_deleted=exclude_deleted,
            level=level,
            pending=pending,
        )

        uuid_documents = (
            Document.resolve_uuid(self.session, resolve_documents)
            if resolve_documents is not None
            else None
        )

        # NOTE: In the case of post, a document just has to not be deleted.
        #       It is easier (for now) to just write out the query here.
        q: Any
        if self.method == H.POST:
            if uuid_documents is None:
                raise ValueError("`uuid_documents` is `None`.")
            q = select(Document).where(Document.uuid.in_(uuid_documents))
            q = q.where(Document.deleted == false())
            resolve_documents = tuple(self.session.scalars(q))
        else:
            q = user.q_select_documents(
                uuid_documents,
                **document_kwargs,
                exclude_pending=not pending,
            )
            resolve_documents = tuple(self.session.execute(q).scalars())

        token_user_grants: Dict[str, Grant] = dict()
        documents = self.document(
            resolve_documents,
            **document_kwargs,
            resolve_user_token=user_token,
            grants=token_user_grants,
            grants_index="uuid_document",
            validate=validate,
            # pending_from=pending_from,
        )

        # NOTE: If the token user is not the user that the data is for then
        #       it is necessary to find a different set of grants.
        grants_user: Dict[str, Grant]
        if user_token.uuid != user.uuid:
            _ = self.document(
                documents,
                **document_kwargs,
                resolve_user_token=user,
                grants=(grants_user := dict()),
                grants_index="uuid_document",
            )
        else:
            grants_user = token_user_grants

        if self.method == H.PATCH and len(
            bad := {
                uuid_document
                for uuid_document, grant in grants_user.items()
                if grant.pending_from != PendingFrom.grantee
            }
        ):
            # NOTE: Ensure all documents have the currect pending from value
            #       for approval
            raise ErrUpdateGrantPendingFrom.httpexception(
                "_msg_grantee",
                403,
                uuid_obj=bad,
                kind_obj=KindObject.document,
            )

        if return_data:
            return mwargs(
                Data[ResolvedGrantUser],
                data=mwargs(
                    ResolvedGrantUser,
                    documents=documents,
                    user=user,
                    grants=grants_user,
                    kind="grant_user",
                    token_user=self.token_user,
                    token_user_grants=token_user_grants,
                ),
                token_user=user_token,
                event=None,
            )
        return user, documents

    def d_grant_user(
        self,
        resolve_user: ResolvableSingular[User],
        resolve_documents: ResolvableMultiple[Document] | None,
        *,
        resolve_user_token: ResolvableSingular | None = None,
        exclude_deleted: bool = True,
        # exclude_pending: bool = True,
        level: ResolvableLevel | None = None,
        pending: bool = False,
        validate: bool = False,
    ) -> Data[ResolvedGrantUser]:
        return self.grant_user(
            resolve_user,
            resolve_documents,
            exclude_deleted=exclude_deleted,
            resolve_user_token=resolve_user_token,
            level=level,
            return_data=True,
            pending=pending,
            validate=validate,
        )

    @overload
    def grant_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_users: ResolvableMultiple[User] | None,
        *,
        resolve_user_token: ResolvableSingular | None = None,
        exclude_deleted: bool = True,
        exclude_pending: bool = False,
        level: ResolvableLevel | None = None,
        return_data: Literal[False] = False,
        pending: bool = False,
    ) -> Tuple[Document, Tuple[User, ...]]: ...

    @overload
    def grant_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_users: ResolvableMultiple[User] | None,
        *,
        resolve_user_token: ResolvableSingular | None = None,
        exclude_deleted: bool = True,
        exclude_pending: bool = False,
        level: ResolvableLevel | None = None,
        return_data: Literal[True] = True,
        pending: bool = False,
    ) -> Data[ResolvedGrantDocument]: ...

    def grant_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_users: ResolvableMultiple[User] | None,
        *,
        resolve_user_token: ResolvableSingular | None = None,
        exclude_deleted: bool = True,
        exclude_pending: bool = False,
        level: ResolvableLevel | None = None,
        return_data: bool = False,
        pending: bool = False,
    ) -> Tuple[Document, Tuple[User, ...]] | Data[ResolvedGrantDocument]:
        """For document owners only."""

        level = Level.resolve(level) if level is not None else self.level
        user_token = self.token_user_or(resolve_user_token)

        token_user_grant: Dict[str, Grant] = dict()
        document = self.document(
            resolve_document,
            exclude_deleted=exclude_deleted,
            resolve_user_token=user_token,
            return_data=False,
            level=Level.own,
            pending=pending,
            grants=token_user_grant,
            grants_index="uuid_user",
        )

        # NOTE: Permissions of users do not matter for CRUD of grants because
        #       they're always url params that are filtered out. Notice:
        #
        #       1. Reading the grants for document requires no knowledge
        #          about the users filtered by.
        #       2. Creating pending grants for a document requires nothing
        #          about the various users to be known with regard to the
        #          source document.
        #       3. Accepting requests for access does not require any grant
        #          knowledge bout the target users on the source document.
        #
        # NOTE: To get grants just use `ResolvedGrant*.grants`.
        users: Tuple[User, ...]
        if resolve_users is None:
            q = document.q_select_users(
                level=Level.own,
                exclude_deleted=exclude_deleted,
                pending=pending,
                exclude_pending=False,
            )
            users = tuple(self.session.execute(q).scalars())
        else:
            users = User.resolve(self.session, resolve_users)

        uuid_users = User.resolve_uuid(self.session, users)
        match self.method:
            # NOTE: Ensure all documents have the currect pending from value
            #       for approval
            case H.GET | H.POST | H.PUT | H.PATCH:
                ...
            case H.DELETE:
                session = self.session
                q_owners = document.q_select_users(
                    level=Level.own,
                    exclude_deleted=exclude_deleted,
                    # pending=pending,
                    exclude_pending=True,  # Absolutely necessary, do not rm
                )

                uuid_owners: set[str]
                uuid_owners = set(item.uuid for item in session.scalars(q_owners))
                if user_token.uuid in uuid_owners:
                    uuid_owners.remove(user_token.uuid)

                if len(uuid_bad := uuid_owners & uuid_users):
                    raise ErrAccessDocumentCannotRejectOwner.httpexception(
                        "_msg_cannot_reject_owner",
                        403,
                        uuid_user_revoker=user_token.uuid,
                        uuid_user_revokees=uuid_bad,
                        uuid_document=Document.resolve_uuid(session, resolve_document),
                    )
            case _:
                raise HTTPException(405)

        q_user_grants = document.q_select_grants(
            uuid_users,
            level=level,
            exclude_pending=exclude_pending,
            pending=pending,
            exclude_deleted=exclude_deleted,
        )
        user_grant: Dict[str, Grant] = {
            grant.uuid_user: grant for grant in self.session.scalars(q_user_grants)
        }

        # NOTE: Check that the grants in question is.
        if self.method == H.PATCH and len(
            bad := {
                uuid_user
                for uuid_user, grant in user_grant.items()
                if grant.pending_from != PendingFrom.granter
            }
        ):
            raise ErrUpdateGrantPendingFrom.httpexception(
                "_msg_granter",
                403,
                uuid_obj=bad,
                kind_obj=KindObject.user,
            )

        if return_data:
            return mwargs(
                Data,
                data=mwargs(
                    ResolvedGrantDocument,
                    document=document,
                    grants=user_grant,
                    users=users,
                    kind="grant_document",
                    token_user_grants=token_user_grant,
                ),
                token_user=user_token,
            )
        return document, users

    def d_grant_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_users: ResolvableMultiple[User] | None,
        *,
        resolve_user_token: ResolvableSingular | None = None,
        exclude_deleted: bool = True,
        exclude_pending: bool = True,
        level: ResolvableLevel | None = None,
        pending: bool = False,
    ) -> Data[ResolvedGrantDocument]:
        return self.grant_document(
            resolve_document,
            resolve_users,
            exclude_deleted=exclude_deleted,
            resolve_user_token=resolve_user_token,
            level=level,
            return_data=True,
            pending=pending,
            exclude_pending=exclude_pending,
        )

    # ----------------------------------------------------------------------- #
    # Assignments

    @overload
    def assignment_collection(  # type: ignore[overload-overlap]
        self,
        resolve_collection: ResolvableSingular[Collection],
        resolve_documents: ResolvableMultiple[Document],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        level: ResolvableLevel | None = None,
        return_data: Literal[False] = False,
        allow_public: bool = False,
        allow_public_collection: bool = False,
        validate_documents: bool = True,
    ) -> Tuple[Collection, Tuple[Document, ...]]: ...

    @overload
    def assignment_collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        resolve_documents: ResolvableMultiple[Document],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        level: ResolvableLevel | None = None,
        return_data: Literal[True] = True,
        allow_public: bool = False,
        allow_public_collection: bool = False,
        validate_documents: bool = True,
    ) -> Data[ResolvedAssignmentCollection]: ...

    def assignment_collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        resolve_documents: ResolvableMultiple[Document],
        *,
        resolve_user_token: ResolvableSingular[User] | None = None,
        exclude_deleted: bool = True,
        level: ResolvableLevel | None = None,
        return_data: bool = False,
        allow_public: bool = False,
        allow_public_collection: bool = False,
        validate_documents: bool = True,
    ) -> Tuple[Collection, Tuple[Document, ...]] | Data[ResolvedAssignmentCollection]:
        # NOTE: Keep `token_user` here so that the user is checked.
        token_user = self.token_user_or(resolve_user_token)
        collection = self.collection(
            resolve_collection,
            exclude_deleted=exclude_deleted,
            resolve_user_token=token_user,
            allow_public=allow_public_collection,
            return_data=False,
        )
        documents = self.document(
            resolve_documents,
            level=level or self.level,
            exclude_deleted=exclude_deleted,
            resolve_user_token=token_user,
            allow_public=allow_public,
            validate=validate_documents,
            return_data=False,
        )

        uuid_documents = Document.resolve_uuid(self.session, resolve_documents)
        q_assignments = collection.q_select_assignment(uuid_documents)
        assignments = {
            assignment.uuid_document: assignment
            for assignment in self.session.execute(q_assignments).scalars()
        }

        if return_data:
            return mwargs(
                Data[ResolvedAssignmentCollection],
                data=mwargs(
                    ResolvedAssignmentCollection,
                    kind="assignment_collection",
                    collection=collection,
                    assignments=assignments,
                    documents=documents,
                    uuid_documents=uuid_documents,
                ),
                token_user=token_user,
                event=None,
            )
        return collection, documents

    def d_assignment_collection(
        self,
        resolve_collection: ResolvableSingular[Collection],
        resolve_documents: ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: ResolvableLevel | None = None,
        validate_documents: bool = True,
        allow_public: bool = False,
        allow_public_collection: bool = False,
    ) -> Data[ResolvedAssignmentCollection]:
        return self.assignment_collection(
            resolve_collection,
            resolve_documents,
            exclude_deleted=exclude_deleted,
            resolve_user_token=resolve_user_token,
            level=level,
            return_data=True,
            validate_documents=validate_documents,
            allow_public=allow_public,
            allow_public_collection=allow_public_collection,
        )

    @overload
    def assignment_document(  # type: ignore[overload-overlap]
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_collections: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: ResolvableLevel | None = None,
        return_data: Literal[False] = False,
        validate_collections: bool = True,
        validate_document: bool = True,
        allow_public: bool = False,
        all_collections: bool = False,
    ) -> Tuple[Document, Tuple[Collection, ...]]: ...

    @overload
    def assignment_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_collections: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: ResolvableLevel | None = None,
        return_data: Literal[True] = True,
        validate_collections: bool = True,
        validate_document: bool = True,
        allow_public: bool = False,
        all_collections: bool = False,
    ) -> Data[ResolvedAssignmentDocument]: ...

    def assignment_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_collections: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: ResolvableLevel | None = None,
        return_data: bool = False,
        validate_collections: bool = True,
        validate_document: bool = True,
        allow_public: bool = False,
        all_collections: bool = False,
    ) -> Tuple[Document, Tuple[Collection, ...]] | Data[ResolvedAssignmentDocument]:
        token_user = self.token_user_or(resolve_user_token)
        document = self.document(
            resolve_document,
            level=level or self.level,
            exclude_deleted=exclude_deleted,
            resolve_user_token=token_user,
            allow_public=allow_public,
            validate=validate_document,
            return_data=False,
        )
        if validate_collections:
            collections = self.collection(
                resolve_collections,
                exclude_deleted=exclude_deleted,
                resolve_user_token=token_user,
            )
        else:
            collections = Collection.resolve(self.session, resolve_collections)

        if all_collections:
            collections = tuple(
                collection
                for collection in collections
                if collection.public or collection.uuid_user == token_user.uuid
            )

        uuid_collections = Collection.resolve_uuid(self.session, resolve_collections)
        q_assignments = document.q_select_assignment(
            uuid_collections, exclude_deleted=exclude_deleted
        )
        assignments = {
            assignment.uuid_collection: assignment
            for assignment in self.session.execute(q_assignments).scalars()
        }

        if return_data:
            return mwargs(
                Data,
                data=mwargs(
                    ResolvedAssignmentDocument,
                    kind="assignment_document",
                    document=document,
                    collections=collections,
                    assignments=assignments,
                ),
                token_user=token_user,
                event=None,
            )

        return document, collections

    def d_assignment_document(
        self,
        resolve_document: ResolvableSingular[Document],
        resolve_collections: ResolvableMultiple[Collection],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: ResolvableLevel | None = None,
        validate_collections: bool = True,
        allow_public: bool = False,
        validate_document: bool = True,
        all_collections: bool = False,
    ) -> Data[ResolvedAssignmentDocument]:
        return self.assignment_document(
            resolve_document,
            resolve_collections,
            exclude_deleted=exclude_deleted,
            resolve_user_token=resolve_user_token,
            level=level,
            return_data=True,
            validate_collections=validate_collections,
            allow_public=allow_public,
            validate_document=validate_document,
            all_collections=all_collections,
        )

    def assignment(
        self,
        source: Document | Collection,
        resolve_target: ResolvableMultiple[Collection] | ResolvableMultiple[Document],
        *,
        exclude_deleted: bool = True,
        resolve_user_token: ResolvableSingular[User] | None = None,
        level: ResolvableLevel | None = None,
    ) -> Data[ResolvedAssignmentDocument] | Data[ResolvedAssignmentCollection]:
        match [source, resolve_target]:
            case [Document() as document, set() | tuple() as targets]:
                return self.assignment_document(
                    document,
                    targets,
                    exclude_deleted=exclude_deleted,
                    resolve_user_token=resolve_user_token,
                    level=level,
                    return_data=True,
                )
            case [Collection() as collection, set() | tuple() as targets]:
                return self.assignment_collection(
                    collection,
                    targets,
                    exclude_deleted=exclude_deleted,
                    resolve_user_token=resolve_user_token,
                    level=level,
                    return_data=True,
                )
            case _ as bad:
                raise ValueError(f"Unexpected source `{bad}`.")


# =========================================================================== #
# Decorators and ABC.
#
# NOTE: While it is possible to write out callabels with aliases, the LSP
#       feedback is garbage (event though they have correct signatures).
T_WithAccess = TypeVar("T_WithAccess", bound="WithAccess")
P_WithAccess = ParamSpec("P_WithAccess")


def with_access(
    fn_access: Callable[
        Concatenate[Access, P_WithAccess],
        Data,
    ],
) -> Callable[
    [Callable[[T_WithAccess, Data], Data]],
    Callable[Concatenate[T_WithAccess, P_WithAccess], Data],
]:
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

    def __call__(
        fn: Callable[[T_WithAccess, Data], Data]
    ) -> Callable[Concatenate[T_WithAccess, P_WithAccess], Data]:
        @functools.wraps(fn_access)
        def wrapper(
            self,
            *args: P_WithAccess.args,
            **kwargs: P_WithAccess.kwargs,
        ) -> Data:
            # NOTE: `data` should be resolved resolvables. This is why the
            #       signatures must match, and further, the output and input
            #       of all controller methods will resolavble data and resolved
            #       outputs.
            data = fn_access(self.access, *args, **kwargs)
            return fn(self, data)

        return wrapper

    return __call__


# NOTE: Decoration -> Simplified signatures. Other methods will be added with
#       prefixes, e.g. ``a_assignment_document``.
class WithAccess(BaseController, abc.ABC):
    # ----------------------------------------------------------------------- #
    access: Access
    api_origin: str
    force: bool = True

    @property
    def event_common(self) -> Dict[str, Any]:
        # TODO: Should use super.
        data = dict(
            api_origin=self.api_origin,
            api_version=__version__,
        )
        # NOTE: Depending on token user might be a mistake.
        if self._token is not None:
            data["uuid_user"] = self.token_user.uuid
        return data

    # NOTE: Why `Resolved` kind names must correspond to their functions. At
    #       this point I am regretting not using a compiled language. This is
    #       here mostly for the reason that in some instances data might be one
    #       of many kinds, therefore it makes sense to be able to excute
    #       functions this way.
    def __call__(self, data: Data[T_Data]) -> Data[T_Data]:
        method_name: str = data.kind
        if (method := getattr(self, method_name, None)) is None:
            raise ValueError(f"`Access` has no method `{method_name}`.")
        return method(data)

    def __init__(
        self,
        session: Session,
        token: Token | Dict[str, Any] | None,
        method: HTTPMethod | str,
        *,
        api_origin: str,
        force: bool = False,
        access: Access | None = None,
    ):
        super().__init__(session, token, method)
        self.force = force
        self.api_origin = api_origin
        self.access = access if access is not None else self.then(Access)

    # ----------------------------------------------------------------------- #
    # Assignments

    @abc.abstractmethod
    def assignment_collection(
        self, data: Data[ResolvedAssignmentCollection]
    ) -> Data[ResolvedAssignmentCollection]: ...

    @abc.abstractmethod
    def assignment_document(
        self, data: Data[ResolvedAssignmentDocument]
    ) -> Data[ResolvedAssignmentDocument]: ...

    # NOTE: Should never overwrite! Messes up overloads!
    @overload
    def assignment(
        self, data: Data[ResolvedAssignmentCollection]
    ) -> Data[ResolvedAssignmentCollection]: ...

    @overload
    def assignment(
        self, data: Data[ResolvedAssignmentDocument]
    ) -> Data[ResolvedAssignmentDocument]: ...

    def assignment(self, data: DataResolvedAssignment) -> DataResolvedAssignment:
        meth = (
            self.assignment_collection
            if data.kind == "assignment_collection"
            else self.assignment_document
        )
        return meth(data)  # type: ignore

    # ----------------------------------------------------------------------- #
    # Grants

    @abc.abstractmethod
    def grant_user(
        self,
        data: Data[ResolvedGrantUser],
    ) -> Data[ResolvedGrantUser]: ...

    @abc.abstractmethod
    def grant_document(
        self,
        data: Data[ResolvedGrantDocument],
    ) -> Data[ResolvedGrantDocument]: ...

    @overload
    def grant(self, data: Data[ResolvedGrantUser]) -> Data[ResolvedGrantUser]: ...

    @overload
    def grant(
        self, data: Data[ResolvedGrantDocument]
    ) -> Data[ResolvedGrantDocument]: ...

    def grant(self, data: DataResolvedGrant) -> DataResolvedGrant:
        meth = self.grant_user if data.kind == "grant_user" else self.grant_document
        return meth(data)  # type: ignore

    # ----------------------------------------------------------------------- #
    # Everything else

    @abc.abstractmethod
    def user(self, data: Data[ResolvedUser]) -> Data[ResolvedUser]: ...

    @abc.abstractmethod
    def document(
        self,
        data: Data[ResolvedDocument],
    ) -> Data[ResolvedDocument]: ...

    @abc.abstractmethod
    def collection(
        self,
        data: Data[ResolvedCollection],
    ) -> Data[ResolvedCollection]: ...
