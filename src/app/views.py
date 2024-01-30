"""Api routers and functions. 
This includes a metaclass so that undecorated functions may be tested.

"""

from http import HTTPMethod
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    Generator,
    Iterable,
    List,
    Literal,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeAlias,
    TypeVar,
    overload,
)

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    HTTPException,
    Path,
    Query,
    WebSocket,
    status,
)
from fastapi.routing import APIRoute
from sqlalchemy import delete, literal_column, or_, select, union, update
from sqlalchemy.engine import Row
from sqlalchemy.orm import Session, make_transient, sessionmaker
from sqlalchemy.sql.expression import false, true

from app import __version__, util
from app.auth import Token, try_decode
from app.depends import (
    DependsAsyncSessionMaker,
    DependsAuth,
    DependsConfig,
    DependsSessionMaker,
    DependsToken,
    DependsTokenOptional,
)
from app.models import (
    AnyModel,
    AssocCollectionDocument,
    AssocUserDocument,
    Collection,
    Document,
    Edit,
    Event,
    KindEvent,
    KindObject,
    KindRecurse,
    Level,
    Tables,
    User,
)
from app.schemas import (
    UUID,
    AssignmentSchema,
    CollectionMetadataSchema,
    CollectionPatchSchema,
    CollectionPostSchema,
    CollectionSchema,
    CollectionSearchSchema,
    DocumentMetadataSchema,
    DocumentSchema,
    DocumentSearchSchema,
    EditMetadataSchema,
    EditSchema,
    EventActionSchema,
    EventBaseSchema,
    EventSchema,
    EventSearchSchema,
    EventWithRootSchema,
    GrantPostSchema,
    GrantSchema,
    KindObjectMinimalSchema,
    ObjectSchema,
    PostUserSchema,
    UserSchema,
    UserSearchSchema,
    UserUpdateSchema,
)

logger = util.get_logger(__name__)
QueryUUIDCollection: TypeAlias = Annotated[Set[str], Query(min_length=1)]
QueryUUIDOwner: TypeAlias = Annotated[Set[str], Query(min_length=1)]
QueryUUIDDocument: TypeAlias = Annotated[Set[str], Query(min_length=1)]
QueryUUIDUser: TypeAlias = Annotated[Set[str], Query(min_length=1)]

PathUUIDUser: TypeAlias = Annotated[str, Path()]
PathUUIDCollection: TypeAlias = Annotated[str, Path()]
PathUUIDDocument: TypeAlias = Annotated[str, Path()]
PathUUIDEvent: TypeAlias = Annotated[str, Path()]

# NOTE: Due to how `q_conds_` works (with empty `set()` versus `None`) the
#       empty set cannot be allowed. When nothing is passed it ought to be
#       `None`.
QueryUUIDCollectionOptional: TypeAlias = Annotated[
    Optional[Set[str]], Query(min_length=1)
]
QueryUUIDDocumentOptional: TypeAlias = Annotated[
    Optional[Set[str]], Query(min_length=1)
]
QueryUUIDUserOptional: TypeAlias = Annotated[Optional[Set[str]], Query(min_length=1)]
QueryUUIDEditOptional: TypeAlias = Annotated[Optional[Set[str]], Query(min_length=1)]

QueryLevel: TypeAlias = Annotated[Literal["view", "modify", "own"], Query()]
QueryRestore: TypeAlias = Annotated[bool, Query()]
QueryTree: TypeAlias = Annotated[bool, Query()]
QueryRoots: TypeAlias = Annotated[bool, Query()]
QueryKindEvent: TypeAlias = Annotated[Optional[KindEvent], Query()]
QueryKindObject: TypeAlias = Annotated[Optional[KindObject], Query()]
QueryUUIDEventObject: TypeAlias = Annotated[Optional[str], Query()]
QueryFlat: TypeAlias = Annotated[bool, Query()]
QueryKindRecurse: TypeAlias = Annotated[Optional[KindRecurse], Query()]
QueryForce: TypeAlias = Annotated[bool, Query()]


# =========================================================================== #
# Base Views.


class ViewMixins:
    """

    :attr view_children: Dictionary of instances to instances.
    :attr view_router: The router built by :class:`ViewMeta`.
    :attr view: Mapping from router function names to router routes.
    """

    # view_children: ClassVar[Dict[str, Type]] = dict()
    view_children: ClassVar[Dict[str, "ViewMeta"]] = dict()
    view_router: ClassVar[APIRouter]
    view_router_args: ClassVar[Dict[str, Any]] = dict()
    view_routes: ClassVar[Dict[str, str]] = dict()


class ViewMeta(type):
    """Metaclass to handle routing.

    It will build a router under `view`.
    """

    @classmethod
    def add_route(cls, T, name_fn: str, route: APIRoute):
        name = T.__name__

        # Parse name
        raw, _ = name_fn.split("_", 1)
        http_meth = next((hh for hh in HTTPMethod if hh.value.lower() == raw), None)
        if http_meth is None:
            logger.warning(f"Could not determine method of `{name_fn}`.")
            return

        # Find attr
        fn = getattr(T, name_fn, None)
        if fn is None:
            msg = f"No such method `{name_fn}` of `{name}`."
            raise ValueError(msg)

        # Create decorator kwargs
        kwargs = dict()
        if http_meth == HTTPMethod.POST:
            kwargs.update(status_code=201)

        # kwargs.update(views_route_args)

        # Get the decoerator and call it.
        logger.debug("Adding function `%s` at route `%s`.", fn.__name__, route)
        decorator = getattr(T.view_router, http_meth.value.lower())
        decorator(route, **kwargs)(fn)

    def __new__(cls, name, bases, namespace):
        T = super().__new__(cls, name, bases, namespace)
        logger.debug("Validating `%s` router.", name)

        # Validate `view_children`.
        if not hasattr(T, "view_children"):
            raise ValueError(f"`{name}` must define `view_children`.")
        elif not isinstance(T.view_children, dict):  # type: ignore
            raise ValueError(f"`{name}.view_children` must be a `dict`.")

        # Validate `view`.
        if not hasattr(T, "view_routes"):
            raise ValueError(f"`{name}` must define `view`.")
        elif not isinstance(T.view_routes, dict):  # type: ignore
            raise ValueError(f"`{name}.view` must be a dict.")

        # Validate `view_router_args`.
        if not hasattr(T, "view_router_args"):
            raise ValueError(f"`{name}` must define `view_router_args`.")
        elif not isinstance(T.view_router_args, dict):  # type: ignore
            raise ValueError(f"`{name}.view_router_args` must be a `dict`.")

        if name != "BaseView":
            # Create router.
            logger.debug("Creating router for `%s`.", name)
            T.view_router = (  # type: ignore
                T.view_router  # type: ignore
                if hasattr(T, "view_router")
                else APIRouter(**T.view_router_args)  # type: ignore
            )
            for name_fn, route in T.view_routes.items():  # type: ignore
                cls.add_route(T, name_fn, route)

            for child_prefix, child in T.view_children.items():  # type: ignore
                logger.debug(
                    "Adding child router `%s` for `%s`.",
                    child_prefix,
                    name,
                )
                T.view_router.include_router(  # type: ignore
                    child.view_router,
                    prefix=child_prefix,
                )

        return T


class BaseView(ViewMixins, metaclass=ViewMeta): ...


# =========================================================================== #
# Views


class DocumentView(BaseView):
    view_routes = dict(
        get_document="/{uuid_document}",
        get_documents="",
        post_document="",
        put_document="/{uuid_document}",
        delete_document="/{uuid_document}",
        get_document_edits="/{uuid_document}/edits",
    )

    @classmethod
    def get_document(
        cls,
        makesession: DependsSessionMaker,
        uuid_document: PathUUIDDocument,
        token: DependsTokenOptional = None,
    ) -> DocumentSchema:
        with makesession() as session:
            document = Document.if_exists(session, uuid_document).check_not_deleted(410)
            if not token:
                if not document.public:
                    msg = "User cannot access document."
                    detail = dict(uuid_document=uuid_document, msg=msg)
                    raise HTTPException(403, detail=detail)
            else:
                cls.verify_access(session, token, document, level=Level.view)

            return document  # type: ignore

    @classmethod
    def get_documents(
        cls,
        token: DependsTokenOptional,
        makesession: DependsSessionMaker,
        params: DocumentSearchSchema = Depends(),
    ) -> List[DocumentMetadataSchema]:
        with makesession() as session:
            q = Document.q_search(
                token.get("uuid") if token is not None else None,
                params.uuid_document,
                name_like=params.name_like,
                description_like=params.description_like,
                all_=params.all_,
            )
            return list(
                DocumentMetadataSchema.model_validate(item)
                for item in session.execute(q)
            )

    @classmethod
    def get_document_edits(
        cls,
        token: DependsToken,
        makesession: DependsSessionMaker,
        uuid: PathUUIDUser,
    ): ...

    # TODO: When integration tests are written, all CUD endpoints should
    #       test that the private CUD fields are approprietly set.
    @classmethod
    def post_document(
        cls,
        token: DependsToken,
        makesession: DependsSessionMaker,
        documents_raw: List[DocumentSchema],
        uuid_collection: QueryUUIDCollection = set(),
        uuid_owner: QueryUUIDOwner = set(),
    ):
        uuid = token["uuid"]
        with makesession() as session:
            # Add the documents
            logger.debug("Adding new documents for user `%s`.", uuid)
            documents = {
                document.name: Document(**document.model_dump())
                for document in documents_raw
            }
            session.add_all(documents.values())
            session.commit()

            # Add user ownership for documents.
            logger.debug("Defining ownership of new documents.")
            user_uuids = [uuid, *uuid_owner]
            users: List[User] = list(
                session.execute(
                    select(User).where(User.uuid.in_(user_uuids)),
                ).scalars()
            )

            # NOTE: This must be done directly creating associations because of
            #       the ``_created_by_uuid_user`` and ``_updated_by_uuid_user``
            #       fields.
            assocs_owners = list(
                AssocUserDocument(
                    user_id=user,
                    document_id=document,
                    level="owner",
                )
                for document in documents.values()
                for user in users
            )
            session.add_all(assocs_owners)
            session.commit()

            logger.debug("Adding document to collections `%s`.", uuid_collection)
            collections: List[Collection] = list(
                session.execute(
                    select(Collection).where(
                        Collection.uuid.in_(uuid_collection),
                    )
                ).scalars()
            )
            assocs_collections = list(
                AssocCollectionDocument(
                    id_document=document.id,
                    id_collection=collection.id,
                )
                for document in documents
                for collection in collections
            )
            session.add_all(assocs_collections)
            session.commit()

            return dict(
                documents={dd.uuid: dd.name for dd in documents},
                assoc_collections=list(aa.uuid for aa in assocs_collections),
                assoc_document_owners=user_uuids,
            )

    @classmethod
    def put_document(cls, filter_params):
        # Take current document content and turn it into a document history.
        ...

    @classmethod
    def delete_document(
        cls,
        token: DependsToken,
        sessionmaker: DependsSessionMaker,
        uuid_document: PathUUIDDocument,
    ):
        with sessionmaker() as session:
            user, document = cls.verify_access(session, token, uuid_document, Level.own)
            # event_assignments = AssignmentView.delete_assignment(
            #     sessionmaker, token, uuid_collection
            # )

    @overload
    @classmethod
    def verify_access(
        cls,
        session: Session,
        token: DependsToken | User,
        uuid_document: PathUUIDDocument | Document,
        *,
        level: Level,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Document]: ...

    @overload
    @classmethod
    def verify_access(
        cls,
        session: Session,
        token: DependsToken | User,
        uuid_document: QueryUUIDDocument | List[Document],
        *,
        level: Level,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Tuple[Document, ...]]: ...

    @classmethod
    def verify_access(
        cls,
        session: Session,
        token: DependsToken | User,
        uuid_document: PathUUIDDocument | QueryUUIDDocument | Document | List[Document],
        *,
        level: Level,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Document] | Tuple[User, Tuple[Document, ...]]:
        if isinstance(token, dict):
            user = User.if_exists(session, token["uuid"], 403)
        else:
            user = token

        user = user.check_not_deleted(410)

        def check_one(document: Document) -> Document:
            # NOTE: Exclude deleted is only required for force deletion.
            if exclude_deleted:
                document = document.check_not_deleted(410)
            user.check_can_access_document(document, level)
            return document

        if isinstance(uuid_document, str):
            documents = Document.if_exists(session, uuid_document)
            return user, check_one(documents)
        elif isinstance(uuid_document, set):
            documents = Document.if_many(session, uuid_document, check_one)
            return user, documents
        elif isinstance(uuid_document, Document):
            return user, check_one(uuid_document)
        elif isinstance(uuid_document, list):
            return user, tuple(check_one(item) for item in uuid_document)
        else:
            msg = f"Unexpected input of type `{type(uuid_document)}`."
            raise ValueError(msg)


class CollectionView(BaseView):
    """Routes for collection CRUD and metadata."""

    view_routes = dict(
        get_collection="/{uuid_collection}",
        get_collections="",
        get_collection_documents="/{uuid_collection}/documents",
        delete_collection="/{uuid_collection}",
        patch_collection="/{uuid_collection}",
        post_collection="",
    )

    @overload
    @classmethod
    def verify_access(
        cls,
        session: Session,
        token: DependsToken | User,
        uuid_collection: PathUUIDCollection | Collection,
        *,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Collection]: ...

    @overload
    @classmethod
    def verify_access(
        cls,
        session: Session,
        token: DependsToken,
        uuid_collection: QueryUUIDCollection | Sequence[Collection],
        *,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Tuple[Collection, ...]]: ...

    @classmethod
    def verify_access(
        cls,
        session: Session,
        token: DependsToken | User,
        uuid_collection: (
            PathUUIDCollection | QueryUUIDCollection | Collection | Sequence[Collection]
        ),
        *,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Collection] | Tuple[User, Tuple[Collection, ...]]:
        if isinstance(token, dict):
            user = User.if_exists(session, token["uuid"])
        else:
            user = token

        user.check_not_deleted(410)

        def check_one(collection: Collection) -> Collection:
            # NOTE: `exclude_deleted` should only be ``True`` when a force
            #       deletion is occuring.
            if exclude_deleted:
                collection = collection.check_not_deleted(410)
            user.check_can_access_collection(collection)
            return collection

        if isinstance(uuid_collection, str):
            collections = Collection.if_exists(session, uuid_collection)
            collections = check_one(collections)
            return user, collections
        elif isinstance(uuid_collection, set):
            collections = Collection.if_many(
                session,
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

    @classmethod
    def get_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: PathUUIDCollection,
    ) -> CollectionSchema:
        with sessionmaker() as session:
            user, collection = cls.verify_access(session, token, uuid_collection)
            return CollectionSchema.model_validate(collection)

    @classmethod
    def get_collections(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsTokenOptional = None,
        param: CollectionSearchSchema = Depends(),
    ) -> List[CollectionSchema]:
        with sessionmaker() as session:
            if token:
                _ = User.if_exists(session, token["uuid"]).check_not_deleted(410)

            q = Collection.q_search(
                token.get("uuid") if token is not None else None,
                param.uuid_collection,
                exclude_deleted=True,
                name_like=param.name_like,
                description_like=param.description_like,
                all_=True,
                session=session,
            )
            return list(
                CollectionSchema.model_validate(item) for item in session.execute(q)
            )

    @classmethod
    def get_collection_documents(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: PathUUIDCollection,
        uuid_document: QueryUUIDDocumentOptional = None,
    ) -> List[DocumentMetadataSchema]:
        """Return UUIDS for the documents."""

        with sessionmaker() as session:
            _, collection = cls.verify_access(session, token, uuid_collection)
            documents = list(
                session.execute(
                    collection.q_select_documents(
                        uuid_document,
                        exclude_deleted=True,
                    ),
                ).scalars()
            )
            return documents

    @classmethod
    def delete_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: PathUUIDCollection,
        restore: bool = False,
    ) -> None:  # EventSchema:
        event_common = dict(
            api_version=__version__,
            api_origin="DELETE /collections/<uuid>",
            kind=KindEvent.delete,
            uuid_user=token["uuid"],
            detail=f"Collection {'restored' if restore else 'deleted'}.",
        )
        with sessionmaker() as session:
            collection = Collection.if_exists(
                session, uuid_collection
            ).check_not_deleted()
            user = (
                User.if_exists(session, token["uuid"])
                .check_not_deleted(410)
                .check_can_access_collection(collection)
            )
            if user.id != collection.id_user:
                raise HTTPException(
                    403,
                    detail=dict(
                        msg="User can only delete their own collections.",
                        uuid_user=token["uuid"],
                        uuid_collection=uuid_collection,
                    ),
                )

            collection.deleted = not restore
            session.add(collection)
            session.commit()

            p = select(Document.uuid).join(AssocCollectionDocument)
            p = p.where(AssocCollectionDocument.id_collection == collection.id)
            q = select(literal_column("uuid"))
            q = union(q.select_from(collection.q_select_documents()), p)
            uuid_document = set(session.execute(q).scalars())

        event_assign_uuid: str | None = None
        if len(uuid_document):
            event_assign_uuid = AssignmentView.delete_assignment(
                sessionmaker,
                token,
                uuid_collection,
                uuid_document,
                restore=restore,
            ).uuid

        with sessionmaker() as session:
            event = Event(
                **event_common,
                kind_obj=KindObject.collection,
                uuid_obj=token["uuid"],
            )

            if event_assign_uuid is not None:
                q = select(Event).where(Event.uuid == event_assign_uuid)
                event_assignment = session.execute(q).scalar()
                assert event_assignment is not None

                detail = event_assignment.detail
                detail = detail.replace(".", " (DELETE /collections/<uuid>).")
                event_assignment.update(
                    session,
                    api_origin=event_common["api_origin"],
                    detail=detail,
                )
                event.children.append(event_assignment)

            session.add(event)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)

    @classmethod
    def patch_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: PathUUIDCollection,
        updates: CollectionPatchSchema = Depends(),
    ):
        """Update collection details or transfer ownership of collection. To
        assign new documents, please `PUT /assign/document/<uuid>."""
        with sessionmaker() as session:
            collection = Collection.if_exists(session, uuid_collection)
            user = User.if_exists(session, token["uuid"])
            if user.id != collection.id_user:
                raise HTTPException(
                    403,
                    detail=dict(
                        msg="User can only delete their own collections.",
                        uuid_user=token["uuid"],
                        uuid_collection=uuid_collection,
                    ),
                )
            event_common = dict(
                uuid_user=user.uuid,
                kind=KindEvent.update,
                api_origin="PATCH /collections/<uuid>",
                api_version=__version__,
            )
            event = Event(
                **event_common,
                uuid_obj=collection.uuid,
                kind_obj=KindObject.collection,
                detail="Collection updated.",
            )

            updates_dict = updates.model_dump()
            uuid_user_target = updates_dict.pop("uuid_user")
            if uuid_user_target is not None:
                target_user = User.if_exists(
                    session,
                    uuid_user_target,
                    msg="Cannot assign collection to user that does not exist.",
                )
                collection.user = target_user
                event.children.append(
                    Event(
                        **event_common,
                        uuid_obj=target_user.uuid,
                        kind_obj=KindObject.user,
                        detail="Collection ownership transfered.",
                    )
                )
                session.add(event)
                session.add(collection)
                session.commit()
                session.refresh(event)
                session.refresh(collection)

            for key, value in updates_dict.items():
                if value is None:
                    continue
                setattr(collection, key, value)
                event.children.append(
                    Event(
                        **event_common,
                        detail=f"Updated collection {key}.",
                        kind_obj=KindObject.collection,
                    )
                )
            session.add(collection)
            session.commit()

            return EventSchema.model_validate(event)

    @classmethod
    def post_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        data: CollectionPostSchema,
        uuid_document: QueryUUIDDocumentOptional = None,
    ) -> EventSchema:
        event_common = dict(
            api_origin="POST /collections",
            api_version=__version__,
            kind=KindEvent.create,
            uuid_user=token["uuid"],
            detail="Collection created.",
        )
        with sessionmaker() as session:
            # Create collection
            user = User.if_exists(session, token["uuid"])
            collection = Collection(**data.model_dump())
            collection.user = user
            session.add(collection)
            session.commit()
            session.refresh(collection)
            uuid_collection = collection.uuid

        uuid_event_assign: str | None = None
        if uuid_document:
            res = AssignmentView.post_assignment(
                sessionmaker,
                token,
                uuid_collection,
                uuid_document,
            ).uuid

        with sessionmaker() as session:
            event = Event(
                **event_common,
                kind_obj=KindObject.collection,
                uuid_obj=collection.uuid,
            )
            if uuid_event_assign is not None:
                event_assignment = session.execute(
                    select(Event).where(Event.uuid == uuid_event_assign)
                ).scalar()
                if event_assignment is None:
                    raise HTTPException(420, detail="Server must be stoned.")
                event.children.append(event_assignment)
                detail = event_assignment.detail
                detail = detail.replace(".", "(POST /collections).")
                event_assignment.update(
                    api_origin=event_common["api_origin"],
                    detail=detail,
                )

            session.add(event)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)


# NOTE: Should mirron :class:`GrantView`. Updates not supported, scoped by
#       collection.
class AssignmentView(BaseView):
    view_routes = dict(
        delete_assignment_collection="/collections/{uuid_collection}",
        post_assignment_collection="/collections/{uuid_collection}",
        get_assignment_collection="/collections/{uuid_collection}",
        delete_assignment_document="/documents/{uuid_document}",
        post_assignment_document="/documents/{uuid_document}",
        get_assignment_document="/documents/{uuid_document}",
    )

    @classmethod
    def verify_access(
        cls,
        session: Session,
        token: DependsToken,
        uuid_collection: Set[str],
        *,
        uuid_document: Set[str],
        level: Level,
        exclude_deleted: bool = True,
    ) -> Tuple[User, Tuple[Document, ...], Tuple[Collection, ...]]:
        user, collections = CollectionView.verify_access(
            session,
            token,
            uuid_collection,
            exclude_deleted=exclude_deleted,
        )
        user, documents = DocumentView.verify_access(
            session,
            user,
            uuid_document,
            level=level,
            exclude_deleted=exclude_deleted,
        )

        return user, documents, collections

    @classmethod
    def split_assignments(
        cls,
        session: Session,
        item,
        uuid_values: Set[str],
        uuid_column,
    ) -> Tuple[Set[str], Set[str]]:
        q = item.q_select_assignment(uuid_values, exclude_deleted=False)
        exps = tuple(
            select(uuid_column).select_from(
                q.where(AssocCollectionDocument.deleted == bool_()).subquery()
            )
            for bool_ in (true, false)
        )

        out = tuple(set(session.execute(exp).scalars()) for exp in exps)
        return out  # type: ignore

    @classmethod
    def delete_assignment_document(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_document: PathUUIDDocument,
        uuid_collection: QueryUUIDCollection,
        force: QueryForce = False,
    ) -> EventSchema:
        with sessionmaker() as session:
            user, (document,), _ = cls.verify_access(
                session,
                token,
                uuid_document={uuid_document},
                uuid_collection=uuid_collection,
                level=Level.own,
                exclude_deleted=False,
            )

            # NOTE: Ignore entries that are already deletd.
            uuid_assign_deleted, uuid_assign_active = cls.split_assignments(
                session, document, uuid_collection, literal_column("uuid")
            )

            if force:
                detail = "Assignment force deleted."
                uuid_assign_active |= uuid_assign_deleted
                q_del = delete(AssocCollectionDocument).where(
                    AssocCollectionDocument.uuid.in_(uuid_assign_active)
                )
            else:
                detail = "Assignment deleted."
                q_del = (
                    update(AssocCollectionDocument)
                    .where(AssocCollectionDocument.uuid.in_(uuid_assign_active))
                    .values(deleted=True)
                )

            # DELETED ALREADY EXCLUDED IN NON FORCE CASE
            uuid_collection_wassign_active = set(
                session.execute(
                    select(Collection.uuid)
                    .join(AssocCollectionDocument)
                    .where(AssocCollectionDocument.uuid.in_(uuid_assign_active))
                ).scalars()
            )
            q_assocs = document.q_select_assignment(
                uuid_collection_wassign_active,
                exclude_deleted=False,
            )
            assocs = list(session.execute(q_assocs).scalars())

            event_common: Dict[str, Any] = dict(
                api_origin="DELETE /assignments/documents/<uuid>",
                api_version=__version__,
                detail=detail,
                uuid_user=user.uuid,
                kind=KindEvent.delete,
            )

            session.add(
                event := Event(
                    **event_common,
                    kind_obj=KindObject.document,
                    uuid_obj=document.uuid,
                    children=[
                        Event(
                            **event_common,
                            kind_obj=KindObject.collection,
                            uuid_obj=assoc.uuid_collection,
                            children=[
                                Event(
                                    **event_common,
                                    kind_obj=KindObject.assignment,
                                    uuid_obj=assoc.uuid,
                                )
                            ],
                        )
                        for assoc in assocs
                    ],
                )
            )
            session.execute(q_del)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)

    @classmethod
    def delete_assignment_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: PathUUIDCollection,
        uuid_document: QueryUUIDDocument,
        force: QueryForce = False,
    ) -> EventSchema:
        with sessionmaker() as session:
            print("========================================================")
            user, _, (collection,) = cls.verify_access(
                session,
                token,
                uuid_collection={uuid_collection},
                uuid_document=uuid_document,
                level=Level.view,
            )
            uuid_assign_deleted, uuid_assign_active = cls.split_assignments(
                session, collection, uuid_document, literal_column("uuid")
            )
            if force:
                detail = "Assignment force deleted."
                uuid_assign_active |= uuid_assign_deleted
                q_del = delete(AssocCollectionDocument).where(
                    AssocCollectionDocument.uuid.in_(uuid_assign_active)
                )
            else:
                detail = "Assignment deleted."
                q_del = (
                    update(AssocCollectionDocument)
                    .where(AssocCollectionDocument.uuid.in_(uuid_assign_active))
                    .values(deleted=True)
                )

            # NOTE: DO NOT EXCLUDED DELETED VALUES IN `q_select_assignment`.
            #       DELETED VALUES MAY EXIST AND REQUIRE FORCE DELETION.
            uuid_docs_active = set(
                session.execute(
                    select(Document.uuid)
                    .join(AssocCollectionDocument)
                    .where(AssocCollectionDocument.uuid.in_(uuid_assign_active))
                ).scalars()
            )
            q_assocs = collection.q_select_assignment(
                uuid_docs_active, exclude_deleted=False
            )
            util.sql(session, q_assocs)
            assocs = list(session.execute(q_assocs).scalars())

            # Create events
            event_common = dict(
                api_origin="DELETE /assignments/collections/<uuid>",
                api_version=__version__,
                kind=KindEvent.delete,
                uuid_user=user.uuid,
                detail=detail,
            )
            event = Event(
                **event_common,
                kind_obj=KindObject.collection,
                uuid_obj=collection.uuid,
                children=[
                    session.refresh(assoc)
                    or Event(
                        **event_common,
                        kind_obj=KindObject.document,
                        uuid_obj=assoc.uuid_document,
                        children=[
                            Event(
                                **event_common,
                                kind_obj=KindObject.assignment,
                                uuid_obj=assoc.uuid,
                            )
                        ],
                    )
                    for assoc in assocs
                ],
            )

            session.add(event)
            session.execute(q_del)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)

    @classmethod
    def post_assignment_document(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_document: PathUUIDDocument,
        uuid_collection: QueryUUIDCollection,
    ) -> EventSchema:
        with sessionmaker() as session:
            (user, (document,), collections) = cls.verify_access(
                session,
                token,
                uuid_document={uuid_document},
                uuid_collection=uuid_collection,
                level=Level.view,
            )

            # Collection uuids for existing and deleted assignments
            lit = literal_column("uuid_collection")
            uuid_assign_deleted, uuid_assign_active = cls.split_assignments(
                session, document, uuid_collection, lit
            )

            if uuid_assign_deleted:
                raise HTTPException(
                    400,
                    detail=dict(
                        uuid_user=user.uuid,
                        uuid_document=document.uuid,
                        uuid_collection=list(uuid_assign_deleted),
                        msg="Assignments must be hard deleted to re-`POST`.",
                    ),
                )

            assocs = [
                AssocCollectionDocument(
                    id_collection=collection.id,
                    id_document=document.id,
                )
                for collection in collections
                if collection.uuid not in uuid_assign_active
            ]
            session.add_all(assocs)
            session.commit()

            event_common = dict(
                api_origin="POST /assignments/document/<uuid>",
                api_version=__version__,
                kind=KindEvent.create,
                uuid_user=token["uuid"],
                detail="Assignment created.",
            )
            event = Event(
                **event_common,
                kind_obj=KindObject.document,
                uuid_obj=document.uuid,
                children=[
                    session.refresh(assoc)
                    or Event(
                        **event_common,
                        kind_obj=KindObject.collection,
                        uuid_obj=assoc.uuid_collection,
                        children=[
                            Event(
                                kind_obj=KindObject.assignment,
                                uuid_obj=assoc.uuid,
                                **event_common,
                            )
                        ],
                    )
                    for assoc in assocs
                ],
            )

            session.add(event)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)

    @classmethod
    def post_assignment_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: PathUUIDCollection,
        uuid_document: QueryUUIDDocument,
    ) -> EventSchema:
        with sessionmaker() as session:
            user, documents, (collection,) = cls.verify_access(
                session,
                token,
                uuid_collection={uuid_collection},
                uuid_document=uuid_document,
                level=Level.view,
            )

            uuid_doc_deleted, uuid_doc_active = cls.split_assignments(
                session,
                collection,
                uuid_document,
                literal_column("uuid_document"),
            )
            if uuid_doc_deleted:
                raise HTTPException(
                    400,
                    detail=dict(
                        uuid_user=user.uuid,
                        uuid_document=list(uuid_doc_deleted),
                        uuid_collection=collection.uuid,
                        msg="Assignments must be hard deleted to re-`POST`.",
                    ),
                )

            # Create
            assocs = list(
                AssocCollectionDocument(
                    id_document=document.id,
                    id_collection=collection.id,
                )
                for document in documents
                if document.uuid not in uuid_doc_active
            )
            session.add_all(assocs)
            session.commit()

            # Create events
            event_common = dict(
                api_origin="POST /assignments/collections/<uuid>",
                api_version=__version__,
                kind=KindEvent.create,
                uuid_user=token["uuid"],
                detail="Assignment created.",
            )
            session.add(
                event := Event(
                    **event_common,
                    kind_obj=KindObject.collection,
                    uuid_obj=collection.uuid,
                    children=[
                        session.refresh(assoc)
                        or Event(
                            **event_common,
                            kind_obj=KindObject.document,
                            uuid_obj=assoc.uuid_document,
                            children=[
                                Event(
                                    **event_common,
                                    kind_obj=KindObject.assignment,
                                    uuid_obj=assoc.uuid,
                                )
                            ],
                        )
                        for assoc in assocs
                    ],
                )
            )
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)

    @classmethod
    def get_assignment_collection(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_collection: PathUUIDCollection,
        uuid_document: QueryUUIDDocumentOptional = None,
    ) -> List[AssignmentSchema]:
        with sessionmaker() as session:
            _, collection = CollectionView.verify_access(
                session, token, uuid_collection=uuid_collection
            )
            q = collection.q_select_assignment(
                uuid_document,
                exclude_deleted=True,
            )
            res = session.execute(q).scalars()

            return list(AssignmentSchema.model_validate(item) for item in res)

    @classmethod
    def get_assignment_document(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_document: PathUUIDDocument,
        uuid_collection: QueryUUIDCollectionOptional = None,
    ) -> List[AssignmentSchema]:
        with sessionmaker() as session:
            _, document = DocumentView.verify_access(
                session, token, uuid_document, level=Level.view
            )
            q = document.q_select_assignment(
                uuid_collection,
                exclude_deleted=True,
            )

            res = session.execute(q).scalars()
            return list(AssignmentSchema.model_validate(item) for item in res)


class GrantView(BaseView):
    # NOTE: Updates should not be supported. It makes more sense to just delete
    #       the permissions and create new ones.
    view_routes = dict(
        delete_grants="/documents/{uuid_document}",
        post_grants="/documents/{uuid_document}",
        get_grants_document="/documents/{uuid_document}",
        get_grants_user="/users/{uuid_user}",
    )

    @classmethod
    def verify_grantees(
        cls,
        session: Session,
        uuid_user: QueryUUIDUser,
    ) -> None:
        """Provided :param:`uuid_user`, look for uuids that do not exist.

        :param session: A session.
        :param uuid_user: Users to check for.
        :returns: Nothing.
        """

        q_uuid_users = select(User.uuid).where(
            User.uuid.in_(uuid_user),
            User.deleted == false(),
        )
        uuid_user_existing = set(session.execute(q_uuid_users).scalars())

        if len(bad := uuid_user - uuid_user_existing):
            detail = dict(
                msg="Cannot grant to users that do not exist.",
                uuid_user=bad,
            )
            raise HTTPException(400, detail=detail)

    @classmethod
    def delete_grants(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_document: PathUUIDDocument,
        uuid_user: QueryUUIDUser,
    ) -> EventSchema:
        """Revoke access to the specified users on the specified document."""

        # NOTE: Permissions should be hard deleted unlike first class rows.
        #       Make sure that the revoker owns the specified document.
        uuid_revoker = token["uuid"]
        with makesession() as session:
            # logger.debug("Verifying document ownership.")
            document: Document = Document.if_exists(
                session, uuid_document
            ).check_not_deleted()
            (
                User.if_exists(session, uuid_revoker, 403)
                .check_not_deleted()
                .check_can_access_document(document, Level.own)
            )

            # NOTE: Look for users that do not exist or are deleted.
            cls.verify_grantees(session, uuid_user)

            # NOTE: Since owners cannot reject the ownership of other owners.
            # logger.debug("Verifying revokee permissions.")
            q_select_grants = document.q_select_grants(uuid_user)
            uuid_owners: Set[str] = set(
                session.execute(
                    select(literal_column("uuid_user"))
                    .select_from(q_select_grants)  # type: ignore
                    .where(literal_column("level") == Level.own)
                ).scalars()
            )
            if len(uuid_owners):
                detail = dict(
                    msg="Owner cannot reject grants of other owners.",
                    uuid_user_revoker=uuid_revoker,
                    uuid_user_revokees=uuid_owners,
                    uuid_documents=uuid_document,
                )
                raise HTTPException(403, detail=detail)

            # NOTE: Base event indicates the document, secondary event
            #       indicates the users for which permissions were revoked.
            #       Tertiary event indicates information about the association
            #       object. The shape of the tree is based off of the shape of
            #       the url on which this function can be called, where the
            #       document is first, the users are second, and the grants
            #       exist only as JSON.
            grants = list(session.execute(q_select_grants))
            event_common = dict(
                api_origin="DELETE /grants/documents/<uuid>",
                uuid_user=uuid_revoker,
                kind=KindEvent.grant,
            )
            event = Event(
                **event_common,
                uuid_obj=uuid_document,
                kind_obj=KindObject.document,
                detail="Grants revoked.",
                children=[
                    Event(
                        **event_common,
                        kind_obj=KindObject.user,
                        uuid_obj=uuid_user,
                        detail=f"Grant `{grant.level.name}` revoked.",
                        children=[
                            Event(
                                **event_common,
                                kind_obj=KindObject.grant,
                                uuid_obj=grant.uuid,
                                detail=f"Grant `{grant.level.name}` revoked.",
                            )
                        ],
                    )
                    for grant in grants
                ],
            )
            session.add(event)
            session.execute(
                update(AssocUserDocument)
                .where(document.q_conds_grants(uuid_user))
                .values(deleted=True)
            )
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)  # type: ignore

    @classmethod
    def get_grants_user(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_user: PathUUIDUser,
        uuid_document: QueryUUIDDocumentOptional = None,
    ) -> List[GrantSchema]:
        """Check that a user has access to the specified document.

        This function will likely be called in document CUD. But can be used
        to retrieve truthiness of an access level.
        """

        with makesession() as session:
            user = User.if_exists(session, token["uuid"])
            if user.uuid != uuid_user:
                detail = dict(msg="Users can only read their own grants.")
                raise HTTPException(403, detail=detail)

            assoc = session.execute(user.q_select_grants(uuid_document))
            return [
                GrantSchema(
                    level=aa.level,
                    uuid=aa.uuid,
                    uuid_user=aa.uuid_user,
                    uuid_document=aa.uuid_document,
                )
                for aa in assoc
            ]

    @classmethod
    def get_grants_document(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_document: PathUUIDDocument,
        uuid_user: QueryUUIDUserOptional = None,
    ) -> List[GrantSchema]:
        """List document grants.

        This could be useful somewhere in the UI. For instance, for owners
        granting permissions.
        """

        with makesession() as session:
            # Verify that user has access
            document = Document.if_exists(session, uuid_document).check_not_deleted(410)
            (
                User.if_exists(session, token["uuid"], 403)
                .check_not_deleted(410)
                .check_can_access_document(document, Level.own)
            )

            results = session.execute(document.q_select_grants(uuid_user))
            return [
                GrantSchema(
                    level=aa.level,
                    uuid=aa.uuid,
                    uuid_user=aa.uuid_user,
                    uuid_document=aa.uuid_document,
                )
                for aa in results
            ]

    @classmethod
    def post_grants(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid_document: PathUUIDDocument,
        grants: List[GrantPostSchema],
    ) -> EventSchema:
        """This endpoint can be used to share a document with another user.

        To revoke document access, use ``DELETE`` version of this endpoint. To
        undo grants from this endpoint, just send DELETE request to the same
        url. To this end, this endpoint is indempotent - posting existing
        grants will change nothing in the database, even if you change the
        level specified in the ``POST`` request.

        To see if a user had grants on a particluar document or not, use
        ``GET /grants/documents/<uuid>`` - To see all of a users grants use
        ``GET /grants/users/<uuid>``.


        :param uuid: Target uuid. The user to grant permissions to.
        :param level: Level to grant. One of "view", "modify", or
            "owner".
        :param uuid_document: The uuids of the documents to grant these
            permissions on.
        """

        with makesession() as session:
            # logger.debug("Verifying granter permissions.")
            document: Document = Document.if_exists(
                session, uuid_document
            ).check_not_deleted()

            granter: User = (
                User.if_exists(session, token["uuid"], 403)
                .check_not_deleted()
                .check_can_access_document(document, Level.own)
            )

            uuid_user: Set[str] = set(gg.uuid_user for gg in grants)
            cls.verify_grantees(session, uuid_user)

            # NOTE: Pick out grants that already exist. These grants will not
            #       be created and this will evident from the response.
            # logger.debug("Finding existing grants.")
            column_uuid_user = literal_column("uuid_user")
            q_uuid_grant_existing = select(column_uuid_user).select_from(
                document.q_select_grants(  # type: ignore
                    user_uuids=uuid_user,
                    exclude_deleted=False,
                ).where(AssocUserDocument.deleted == false())
            )
            q_uuid_grant_deleted = select(column_uuid_user).select_from(
                document.q_select_grants(  # type: ignore
                    user_uuids=uuid_user,
                    exclude_deleted=False,
                ).where(AssocUserDocument.deleted == true())
            )
            uuid_grant_existing, uuid_grant_deleted = (
                set(session.execute(q_uuid_grant_existing).scalars()),
                set(session.execute(q_uuid_grant_deleted).scalars()),
            )

            session.execute(
                update(AssocUserDocument)
                .where(AssocUserDocument.uuid.in_(uuid_grant_deleted))
                .values(deleted=False)
            )
            session.commit()
            uuid_grant_existing |= uuid_grant_deleted

            # logger.debug("Creating associations for grants.")
            assocs = {
                gg.uuid_user: AssocUserDocument(
                    id_user=User.if_exists(session, gg.uuid_user).id,
                    id_document=document.id,
                    level=gg.level,
                    deleted=False,
                )
                for gg in grants
                if gg.uuid_user not in uuid_grant_existing
            }
            session.add_all(assocs.values())
            session.commit()

            # NOTE: Events returned by this endpoint should look like those
            #       returned from the corresponding DELETE endpoint.
            logger.debug("Creating events for grant.")
            common = dict(
                kind=KindEvent.grant,
                uuid_user=granter.uuid,
                api_origin="POST /grants/documents/<uuid>",
                api_version=__version__,
            )
            event = Event(
                **common,
                uuid_obj=uuid_document,
                kind_obj=KindObject.document,
                detail="Grants issued.",
                children=[
                    Event(
                        **common,
                        uuid_obj=uuid_user,
                        kind_obj=KindObject.user,
                        detail=f"Grant `{assoc.level.name}` issued.",
                        children=[
                            Event(
                                **common,
                                uuid_obj=assoc.uuid,
                                kind_obj=KindObject.grant,
                                detail=f"Grant `{assoc.level.name}` issued.",
                            )
                        ],
                    )
                    for uuid_user, assoc in assocs.items()
                ],
            )
            session.add(event)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)


class UserView(BaseView):
    """Routes for user data and metadata.

    This will be put on ``/users``.
    """

    view_routes = dict(
        get_users="",
        get_user="/{uuid}",
        patch_user="/{uuid}",
        delete_user="/{uuid}",
        post_user="",
        get_user_documents="/{uuid}/documents",
        get_user_edits="/{uuid}/edits",
        get_user_collections="/{uuid}/collections",
    )

    # ----------------------------------------------------------------------- #
    # READ endpoints.

    @classmethod
    def get_user(
        cls,
        makesession: DependsSessionMaker,
        uuid: PathUUIDUser,
        token: DependsTokenOptional = None,
    ) -> UserSchema:
        """Get user metadata.

        For instance, this should be used to make a profile page.
        """

        with makesession() as session:
            user = User.if_exists(session, uuid, 404)
            print("JERE")
            if user.deleted:
                raise HTTPException(404)
            elif user.public:
                return user  # type: ignore
            # At this point reject bad tokens. A user should be able to read
            # their own account.
            elif user.uuid != token["uuid"]:
                raise HTTPException(401)

            return user  # type: ignore

    # NOTE: The token depends is included since API billing will depend on
    #       users having a valid token. Later I would like to make it such that
    #       it will also accept requests without tokens from particular
    #       origins, for instance a site where articles may be publicly viewed.
    @classmethod
    def get_users(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        param: UserSearchSchema = Depends(),
    ) -> List[UserSchema]:
        """Get user collaborators or just list some users.

        Once authentication is integrated, getting collaborators will be
        possible. Collaborators will only be possible when the caller has an
        account, otherwise some random users should be returned.
        """
        with makesession() as session:
            if token:
                # Find collaborators.
                ...

            # Get public, active documents.
            q = select(User).limit(param.limit)
            if param.name_like is not None:
                q = q.where(User.name.regexp_match(f"^.*{param.name_like}.*$"))
            q = q.where(User.deleted == false())
            q = q.where(User.public == true())

            result: List[User] = list(session.execute(q).scalars())
            return result  # type: ignore

    # NOTE: This should not be decorated but should be used in the individual
    #       getters with clearer (not a union) type hints (the ``child``
    #       parameter will not appear in actual endpoints.).
    @classmethod
    def select_user_child(
        cls,
        child: Literal["collections", "edits", "documents"],
        makesession: sessionmaker[Session],
        uuid: PathUUIDUser,
    ) -> Any:
        """Get user ``collections`` and ``edits`` data without content.

        :param child: Child to get metadata for. Must be one of ``collections``
            or ``edits``. For ``documents`` use the ``/document`` endpoints.
        :param filter_params: Use these parameters to filter out which children
            to display.
        """

        with makesession() as session:
            user: User = User.if_exists(session, uuid)
            if user.deleted:
                raise HTTPException(404)

            children: List[Collection] | List[Edit] | List[Document]
            children = getattr(user, child)

            # if not len(children):
            #     JSONResponse([], 204)

            return children  # type: ignore

    # TODO: Test that users can not access other users' private docs/colls from
    #       here.
    @classmethod
    def get_user_documents(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid: PathUUIDUser,
        uuid_document: QueryUUIDDocumentOptional = None,
    ) -> Dict[str, DocumentMetadataSchema]:
        res = cls.select_user_child(
            "documents",
            makesession,
            uuid,
        )
        if token["uuid"] != uuid:
            res = {k: v for k, v in res.items() if v.public}
        if uuid_document:
            res = {k: v for k, v in res.items() if k in uuid_document}

        return res

    @classmethod
    def get_user_collections(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid: PathUUIDUser,
        uuid_collection: QueryUUIDCollectionOptional = None,
    ) -> Dict[str, CollectionMetadataSchema]:
        res = cls.select_user_child("collections", makesession, uuid)
        if token["uuid"] != uuid:
            res = {k: v for k, v in res.items() if v.public}
        if uuid_collection:
            res = {k: v for k, v in res.items() if k in uuid_collection}

        return res

    @classmethod
    def get_user_edits(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid: PathUUIDUser,
        uuid_edit: QueryUUIDEditOptional = None,
    ) -> List[EditMetadataSchema]:
        res = cls.select_user_child(
            "edits",
            makesession,
            uuid,
        )
        if token["uuid"] != uuid:
            res = [item for item in res if item.public]
        if uuid_document:
            res = [item for item in res if item.uuid in uuid_edit]

    # ----------------------------------------------------------------------- #
    # CRUD without R

    @classmethod
    def patch_user(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid: PathUUIDUser,
        updates: UserUpdateSchema = Depends(),
    ) -> EventSchema:
        """Update a user.

        Only the user themself should be able to update this.
        """
        if not uuid == token["uuid"]:
            raise HTTPException(403, detail="Users can only modify their own account.")

        with makesession() as session:
            user = User.if_exists(session, uuid)

            # NOTE: Don't forget to include the metadata.
            updates_dict = updates.model_dump()
            event_common = dict(
                uuid_user=uuid,
                uuid_obj=uuid,
                kind=KindEvent.update,
                kind_obj=KindObject.user,
                api_origin="PATCH /users/<uuid>",
            )
            event = Event(**event_common, detail="Updated user.")
            for key, value in updates_dict.items():
                if value is None:
                    continue
                setattr(user, key, value)
                event.children.append(
                    Event(**event_common, detail=f"Updated user {key}.")
                )
            session.add(event)
            session.add(user)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)  # type: ignore

    @classmethod
    def delete_user(
        cls,
        makesession: DependsSessionMaker,
        token: DependsToken,
        uuid: PathUUIDUser,
        restore: bool = False,
    ) -> EventSchema:
        """Remove a user and their unshared documents and edits.

        Only the user themself or an admin should be able to call this
        endpoint.
        """
        if not uuid == token["uuid"]:
            raise HTTPException(
                403, detail="Users can only delete/restore their own account."
            )
        with makesession() as session:
            user = User.if_exists(session, uuid)

            api_origin = "DELETE /users/<uuid>"
            msg = "deleted" if not restore else "restored"
            event = Event(
                uuid_user=uuid,
                uuid_obj=uuid,
                kind=KindEvent.delete,
                kind_obj=KindObject.user,
                detail=f"User {msg}.",
                api_origin=api_origin,
            )

            # Get exclusive_documents.
            q = user.q_select_documents_exclusive()
            exclusive_documents = list(session.execute(q).scalars())
            for dd in exclusive_documents:
                event.children.append(
                    Event(
                        uuid_user=uuid,
                        uuid_obj=dd.uuid,
                        kind_obj=KindObject.document,
                        kind=KindEvent.delete,
                        detail=f"Document {msg}.",
                        api_origin=api_origin,
                    )
                )
                session.add(event)

                dd.deleted = not restore
                session.add(dd)

            user.deleted = not restore
            session.add(user)
            session.add(event)
            session.commit()

            return EventSchema.model_validate(event)  # type: ignore

    @classmethod
    def post_user(
        cls,
        makesession: DependsSessionMaker,
        data: PostUserSchema,
    ) -> EventSchema:
        """Create a user.

        For now sharing of collections or documents can be done through
        calling `POST /grant/users/<uuid>/documents/<uuid_document>` endpoints.
        """
        api_origin = "POST /users"
        with makesession() as session:
            session.add(
                user := User(**data.model_dump(exclude={"collections", "documents"}))
            )
            session.commit()
            session.refresh(user)

            events_common = dict(
                uuid_user=user.uuid,
                api_origin=api_origin,
                kind=KindEvent.create,
            )
            session.add(
                event := Event(
                    **events_common,
                    uuid_obj=user.uuid,
                    kind_obj=KindObject.user,
                    detail="User created.",
                )
            )
            session.commit()

            if data.collections:
                session.add_all(
                    collections := [
                        Collection(**cc.model_dump(), id_user=user.id)
                        for cc in data.collections
                    ]
                )

                session.commit()
                session.add_all(
                    [
                        Event(
                            **events_common,
                            uuid_parent=event.uuid,
                            uuid_obj=cc.uuid,
                            kind_obj=KindObject.collection,
                            detail="Collection created.",
                        )
                        for cc in collections
                    ]
                )
                session.commit()
            if data.documents:
                session.add_all(
                    documents := [Document(**dd.model_dump()) for dd in data.documents]
                )
                session.commit()
                user.documents = {dd.name: dd for dd in documents}
                session.add(user)
                session.add_all(
                    [
                        Event(
                            **events_common,
                            uuid_parent=event.uuid,
                            uuid_obj=dd.uuid,
                            kind_obj=KindObject.document,
                            detail="Document created.",
                        )
                        for dd in documents
                    ]
                )
                session.commit()

            session.refresh(event)
            return EventSchema.model_validate(event)


class AuthView(BaseView):
    """This is where routes to handle login and getting tokens will be."""

    view_routes = dict(
        post_token="/token",
        get_login="/login",
        get_token="/token",
    )

    @classmethod
    def post_token(cls, auth: DependsAuth, data: Token) -> str:
        """Use this to create a new token.

        This endpoint only works when authentication is in pytest mode, and
        will not use auth0 mode. NEVER run this application in production while
        using tokens in endpoint mode, it will allow undesired access to user
        information (because anybody could imitate any user by minting a token
        with that particular users UUID).
        """

        return data.try_encode(auth)

    @classmethod
    def get_token(cls, auth: DependsAuth, data: str) -> Token:
        return Token.try_decode(auth, data, header=False)

    @classmethod
    def get_login(cls, config: DependsConfig):
        if not config.auth0.use:
            raise HTTPException(
                409,
                detail="Login is not available in pytest mode.",
            )


class EventView(BaseView):
    """
    ..
        NOTE: Events should never return results in flattened format from
              anywhere besides here.
    """

    view_routes = dict(
        get_event="/{uuid_event}",
        delete_event="/{uuid_event}",
        get_events="",
        patch_undo_event="/{uuid_event}/objects",
        # patch_object="/{uuid_event}/objects/restore/{uuid_obj}",
        # get_event_objects="/{uuid_event}/objects",
    )

    @classmethod
    def delete_event(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_event: PathUUIDEvent,
    ) -> EventSchema:
        with sessionmaker() as session:
            user, event = cls.verify_access(session, token, uuid_event)
            event_root = event.find_root()
            session.delete(event_root)
            session.commit()
            event = Event(
                api_version=__version__,
                api_origin="DELETE /events/<uuid>",
                detail="Event deleted.",
                kind=KindEvent.delete,
                kind_obj=KindObject.event,
                uuid_user=user.uuid,
                uuid_obj=event.uuid,
            )
            session.add(event)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)

    @classmethod
    def get_event(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_event: PathUUIDEvent,
        tree: QueryTree = False,
    ) -> EventSchema:
        with sessionmaker() as session:
            _, event = cls.verify_access(session, token, uuid_event)
            if tree:
                while uuid_parent := event.uuid_parent:
                    event = Event.if_exists(session, uuid_parent)

            return EventSchema.model_validate(event)

    @classmethod
    async def get_events(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        param: EventSearchSchema = Depends(),
        flatten: QueryFlat = True,
        kind_recurse: QueryKindRecurse = KindRecurse.depth_first,
    ) -> List[EventWithRootSchema] | List[EventBaseSchema]:
        with sessionmaker() as session:
            User.if_exists(session, token["uuid"]).check_not_deleted()
            q = Event.q_select_search(token["uuid"], **param.model_dump())
            res = session.execute(q)
            uuid_event: Set[str] = set(res.scalars())

            if flatten:
                q = Event.q_select_recursive(
                    uuid_event,
                    kind_recurse=kind_recurse,
                ).order_by(Event.timestamp)
                events = session.execute(q)
                T = EventWithRootSchema
            else:
                q = Event.q_uuid(uuid_event).order_by(Event.timestamp)
                events = (session.execute(q)).scalars()
                T = EventBaseSchema

            return [T.model_validate(ee) for ee in events]

    ## TODO: Finish this later when time exists for it.
    # @classmethod
    # async def ws_events(
    #     cls,
    #     websocket: WebSocket,
    #     sessionmaker: DependsAsyncSessionMaker,
    #     token: DependsToken,
    #     param: EventSearchSchema = Depends(),
    #     flatten: QueryFlat = True,
    #     kind_recurse: QueryKindRecurse = KindRecurse.depth_first,
    #     wait: Annotated[int, Query(gt=1, lt=60)] = 1,
    # ) -> None:
    #     WS_MAX_LIFETIME: int = 36000
    #
    #     await websocket.accept()
    #     timestamp_connection_start = int(datetime.timestamp(datetime.now()))
    #     lifetime = 0
    #
    #     while (lifetime := lifetime + wait) < WS_MAX_LIFETIME:
    #         # events = await cls.get_events(
    #         #     sessionmaker,
    #         #     token,
    #         #     param=param,
    #         #     flatten=flatten,
    #         #     kind_recurse=kind_recurse,
    #         # )
    #         # await websocket.send_json(events)
    #         # await asyncio.sleep(wait)
    #         text = await websocket.receive_text()
    #         await websocket.send(f"text = `{text}`.")
    #
    #     ...

    @classmethod
    def get_event_objects(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_event: PathUUIDUser,
    ) -> List[EventWithRootSchema]:
        """Restore a deletion from an event."""

        with sessionmaker() as session:
            user, event = cls.verify_access(session, token, uuid_event)
            ...

    @classmethod
    def verify_access(
        cls,
        session: Session,
        token: DependsToken,
        uuid_event: PathUUIDUser,
    ) -> Tuple[User, Event]:
        event = Event.if_exists(session, uuid_event)
        user = (
            User.if_exists(session, token["uuid"])
            .check_can_access_event(event)
            .check_not_deleted(410)
        )

        return user, event

    T = TypeVar("T")

    @classmethod
    def iter_eventobject(
        cls, session: Session, events: List[T]
    ) -> Generator[Tuple[T, AnyModel], None, None]:
        for item in events:
            tt = Tables[item.kind_obj].value
            qq = select(tt).where(tt.uuid == item.uuid_obj)
            oo = session.execute(qq).scalar()
            if oo is None:
                continue
            yield item, oo

    @classmethod
    def patch_undo_event(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid_event: PathUUIDUser,
    ) -> EventActionSchema:
        """Restore a deletion from an event.

        Return the events and updated objects.

        :param dry_run:
        """

        with sessionmaker() as session:
            user, event = cls.verify_access(session, token, uuid_event)
            event.check_kind(KindEvent.delete).check_not_undone()

            # Event for restoring from event.

            event_root = event.find_root().check_kind(KindEvent.delete)
            event_root = event_root.check_not_undone()

            user.check_can_access_event(event_root).check_not_deleted(410)

            event_action = event_root.undone(
                api_version=__version__,
                api_origin="PATCH /events/restore/<uuid>",
                detail="Restored from deletion event.",
                uuid_user=token["uuid"],
            )
            session.add(event_action)

            for item in event.flattened():
                object_ = item.object_
                print(object_)
                if not hasattr(object_, "deleted"):
                    continue
                object_.deleted = False
                session.add(object_)

            session.commit()
            session.refresh(event_action)

            return EventActionSchema.model_validate(
                dict(event_action=event_action, event_root=event_root)
            )

    @classmethod
    def patch_undo_object(cls): ...


class AppView(BaseView):
    view_router = FastAPI()  # type: ignore
    view_routes = {"get_index": "/"}
    view_children = {
        "/grants": GrantView,
        "/assignments": AssignmentView,
        "/users": UserView,
        "/collections": CollectionView,
        "/documents": DocumentView,
        "/auth": AuthView,
        "/events": EventView,
    }

    @classmethod
    def get_index(cls, uuid: int, makesession: DependsSessionMaker) -> None: ...
