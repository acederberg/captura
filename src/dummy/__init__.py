# =========================================================================== #
import secrets
from http import HTTPMethod
from random import choice, randint
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Dict,
    List,
    NotRequired,
    Self,
    Set,
    Tuple,
    Type,
    TypedDict,
)

import httpx
import yaml
from cryptography.utils import cached_property
from sqlalchemy import delete, desc, false, func, or_, select, true, update
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker as _sessionmaker
from typing_extensions import Doc

# --------------------------------------------------------------------------- #
from app import util
from app.auth import Auth, Token, TokenPermissionTier
from app.controllers.access import Access
from app.controllers.base import (
    BaseResolved,
    BaseResolvedPrimary,
    BaseResolvedSecondary,
    Data,
    KindData,
    ResolvedDocument,
    ResolvedUser,
    T_ResolvedPrimary,
)
from app.controllers.delete import Delete
from app.fields import KindEvent, KindObject, Level
from app.models import (
    Assignment,
    AssocCollectionDocument,
    AssocUserDocument,
    Base,
    Collection,
    Document,
    Event,
    Grant,
    KindObject,
    Level,
    PendingFrom,
    ResolvableModel,
    ResolvedRawCollection,
    ResolvedRawDocument,
    User,
    resolve_model,
    uuids,
)
from app.schemas import mwargs
from client import ConsoleHandler, ContextData, Requests
from client.config import Config as ClientConfig
from client.config import ProfileConfig, UseConfig
from client.flags import Output
from client.handlers import ConsoleHandler
from client.requests import Requests
from client.requests.base import ContextData
from dummy.config import ConfigSimulatus, DummyConfig
from dummy.mk import Mk, combos
from dummy.reports import ReportController

util.setup_logging(util.Path.base("logging.test.yaml"))
logger = util.get_logger(__name__)

# =========================================================================== #
# Providers


class GetPrimaryKwargs(TypedDict):
    public: NotRequired[bool | None]
    deleted: NotRequired[bool | None]
    uuids: NotRequired[Set[str] | None]
    retry: NotRequired[bool]
    retry_count_max: NotRequired[int]
    allow_empty: NotRequired[bool]


class GetPrimaryDataKwargs(TypedDict):
    n: NotRequired[int | None]
    get_primary_kwargs: NotRequired[GetPrimaryKwargs]
    other: NotRequired[bool]
    callback: NotRequired[Callable[[Dict[str, Any], Tuple[Any, ...]], None]]


class BaseDummyProvider:
    dummy_kinds: ClassVar[Set[KindObject]] = {
        KindObject.user,
        KindObject.collection,
        KindObject.document,
        KindObject.grant,
        KindObject.assignment,
        KindObject.event,
    }

    client_config_cls: Type
    config: ConfigSimulatus
    dummy: DummyConfig
    session: Session
    user: User
    auth: Auth

    def __init__(
        self,
        config: ConfigSimulatus,
        session: Session,
        *,
        user: User,
        auth: Auth | None = None,
        client_config_cls: Type | None = None,
    ):
        self.client_config_cls = client_config_cls or ClientConfig
        self.config = config
        self.dummy = config.dummy
        self.auth = auth if auth is not None else Auth.forPyTest(config)
        self.session = session
        self.user = user

    # ----------------------------------------------------------------------- #
    # Functions derivative of ``Mk``.

    def mk_user(self) -> User:
        user = Mk.user()
        user.admin = False
        user.deleted = False
        return user

    def mk_documents(self) -> Tuple[Document, ...]:
        # NOTE: Grants cereated in :func:`mk_grants`.
        logger.debug("Making documents.")

        assert isinstance(self.dummy, DummyConfig)
        a, b = self.dummy.minimum_count_documents, self.dummy.maximum_count_documents
        return tuple(Mk.document() for _ in range(randint(a, b)))

    def mk_assignments(
        self,
        documents: Tuple[Document, ...],
        collections: Tuple[Collection, ...],
    ) -> Tuple[Assignment, ...]:
        # NOTE: Iter over collections first so that every document has a chance
        #       belong to each collection.
        # TODO: Make it such that this is not restricted to a user only having
        #       its collections made exclusively of its own documents.
        logger.debug("Making assignments...")
        assignments: Tuple[Assignment, ...] = tuple(
            Assignment(
                id_document=document.id,
                id_collection=collection.id,
                deleted=False,
            )
            for collection in collections
            for document in documents
            if randint(0, 2)
        )
        self.session.add_all(assignments)
        return assignments

    def mk_grants(
        self,
        documents: Tuple[Document, ...],
        exclude_grants_self: bool = False,
        exclude_grants_create: bool = False,
    ):
        dummies = self.dummy

        # NOTE: Adding grants to the database can be a real pain in the ass
        #       because the primary key of the grants table is infact the
        #       ``uuid`` column and not the associated tables since the table
        #       is a tree. For this reason it is advised that a delete
        #       statement be emitted in addition to these queries.
        #
        # TLDR: Do not use ``session.merge``, just use ``DELETE`` or use
        #       options to avoid causing duplicate ``(id_user, id_document)``
        #       keys.
        if not exclude_grants_create:
            logger.debug("Making grants for documents created by self.")
            grants_created = tuple(
                Grant(
                    level=Level.own,
                    id_user=self.user.id,
                    id_document=document.id,
                    deleted=False,
                    pending=False,
                    pending_from=PendingFrom.created,
                )
                for document in documents
            )
        else:
            grants_created = tuple()

        # NOTE: Add grants for documents of other users.
        # NOTE: Grants giving access to documents that exist already.
        if not exclude_grants_self:
            logger.debug("Making grants for `%s` on documents created by others.")
            a, b = dummies.maximum_count_grants_self, dummies.maximum_count_grants_self
            q_ids_has_grants = (
                select(Document.id)
                .join(Grant)
                .group_by(Grant.id_document)
                .having(func.count(Grant.id_user) > 0)
                .where(Grant.id_user == self.user.id)
            )
            q_grants_share = (
                select(Grant)
                .join(Document)
                .where(
                    Document.id.not_in(q_ids_has_grants),
                    Grant.pending_from == PendingFrom.created,
                )
                .limit(b)
                .order_by(func.random())
            )
            grants_share = tuple(self.session.scalars(q_grants_share))

            if (n := len(grants_share)) < a:
                logger.warning(
                    "Only `%s` documents for user `%s`.",
                    n,
                    self.user.uuid,
                )

            grants_self = tuple(
                Grant(
                    uuid=secrets.token_urlsafe(8),
                    id_user=self.user.id,
                    id_document=grant.id_document,
                    uuid_parent=grant.uuid,
                    **kwargs,
                )
                for (grant, kwargs) in zip(grants_share, combos())
            )

        else:
            grants_self = tuple()

        # NOTE: Grants to others on documents created. ``grants_source`` is
        #       included since there is the option to not make ``created`` grants
        #       for the provided documents.
        logger.debug("Making grants for others on documents created `%s`.")

        q_ids_users = (
            select(User.id)
            .where(User.id != self.user.id)
            .limit(
                randint(
                    dummies.minimum_count_grants_other,
                    dummies.maximum_count_grants_other,
                )
            )
        )
        id_users_other = set(self.session.scalars(q_ids_users))

        if not grants_created:
            grants_source = tuple(map(self.get_document_grant, documents))
            assert len(grants_source) == len(documents)
        else:
            grants_source = grants_created

        grants_other = tuple(
            Grant(
                uuid=secrets.token_urlsafe(8),
                level=choice(list(Level)),
                id_user=id_user,
                id_document=grant.id_document,
                uuid_parent=grant.uuid,
                deleted=bool(randint(0, 1)),
                pending=bool(randint(0, 1)),
                pending_from=choice((PendingFrom.grantee, PendingFrom.granter)),
            )
            for grant in grants_source
            for id_user in id_users_other
        )

        return grants_created + grants_self + grants_other

    def mk_collections(self) -> Tuple[Collection, ...]:
        logger.debug("Making collections...")
        dummies = self.dummy
        a, b = dummies.minimum_count_documents, dummies.maximum_count_documents
        return tuple(Mk.collection(user=self.user) for _ in range(randint(a, b)))

    def mk(
        self,
        documents: ResolvedRawDocument | None = None,
        collections: ResolvedRawCollection | None = None,
        # edits: ResolvedRawCollection | None = None,
        create_grants: None | Dict[str, Any] = dict(),  # options for mk_grants
        create_assignments: bool = True,
        create_documents_unique: bool = True,
    ) -> Dict[str, Set[str]]:
        """Set up a new user or add data."""

        # NOTE: Create dummy users, documents, and collections. Grants and
        #       assignments will be made subsequently.
        data: Dict[str, Set[str]] = dict()
        session = self.session
        session.add(self.user)
        session.commit()
        session.refresh(self.user)

        data.update(user={self.user.uuid})

        if documents is None:
            session.add_all(documents := self.mk_documents())
            session.commit()
            data.update(documents=uuids(documents))

        if collections is None:
            session.add_all(collections := self.mk_collections())
            session.commit()
            data.update(collections=uuids(collections))

        # NOTE: Session.merge only works for assignments and not grants because
        #       assignments uses the association primary keys to form a its
        #       primary key while grants uses the uuid. See :func:`mk_grants`.
        if create_assignments:
            assert documents is not None, "Documents required."
            assert collections is not None, "Collections required."
            tuple(
                map(
                    lambda item: session.merge(item),
                    (assignments := self.mk_assignments(documents, collections)),
                )
            )
            session.commit()
            data.update(assignments=uuids(assignments))

        if create_grants is not None:
            assert documents is not None, "Documents required."
            grants = self.mk_grants(documents, **create_grants)

            tuple(
                map(
                    lambda item: session.merge(item),
                    grants,
                )
            )
            session.commit()
            data.update(grants=uuids(grants))

        # NOTE: Create some uniquely owned documents (important for tests of
        #       deltion cascading configuration). It is important to note
        #       that these documents are only gaurenteed to be unique when the
        #       dummy is the most recently generated.
        if create_documents_unique:
            documents_uniq = self.mk_documents()
            session.add_all(documents_uniq)
            session.commit()

            data["documents"] |= uuids(documents_uniq)

        return data

    # ----------------------------------------------------------------------- #
    # Getters

    def randomize_primary(
        self,
        model: ResolvableModel,
        uuids: Set[str] | None = None,
    ) -> None:
        Model = resolve_model(model)

        q = update(Model).where(func.random() < 0.5)
        if uuids is not None:
            q = q.where(Model.uuid.in_(uuids))
        tuple(
            self.session.execute(q.values(deleted=deleted, public=public))
            for deleted in (0, 1)
            for public in (0, 1)
        )
        self.session.commit()

    def randomize_grants(self):
        logger.debug("Randomizing grants for `%s`.", self.user.uuid)
        q_uuids = select(Grant.uuid).where(
            Grant.id_user == self.user.id, Grant.pending_from != PendingFrom.created
        )
        uuids = self.session.scalars(q_uuids)

        for pending in (0, 1):
            for pending_from in (PendingFrom.grantee, PendingFrom.granter):
                q = (
                    update(Grant)
                    .values(pending=pending, pending_from=pending_from)
                    .where(Grant.uuid.in_(uuids), func.random() < 0.5)
                )
                self.session.execute(q)

        self.session.commit()

    def get_primary(
        self,
        model: ResolvableModel,
        n: int,
        *,
        public: bool | None = None,
        deleted: bool | None = False,
        uuids: Set[str] | None = None,
        callback: Callable[[Any], Any] | None = None,
        retry_callback: Callable[[], None] | None = None,
        retry_count: int = 0,
        retry_count_max: int = 1,
        retry: bool = True,
        allow_empty: bool = False,
    ) -> Tuple[T_ResolvedPrimary, ...]:
        Model = resolve_model(model)

        logger.debug("Getting data of kind `%s`.", Model.__tablename__)
        conds = list()
        if public is not None:
            bool_ = true() if public else false()
            conds.append(Model.public == bool_)
        if deleted is not None:
            bool_ = true() if deleted else false()
            conds.append(Model.deleted == bool_)
        if uuids is not None:
            conds.append(Model.uuid.in_(uuids))

        q = select(Model).where(*conds).order_by(func.random()).limit(n)
        if callback:
            q = callback(q)

        # NOTE: Move assertions here to avoid preflight checks in tests.
        models = tuple(self.session.scalars(q))
        if not allow_empty and len(models) == 0:
            logger.debug(
                "Found empty results for kind `%s`.",
                Model.__tablename__,
            )
            if retry and retry_count < retry_count_max:
                self.randomize_primary(Model)

                if retry_callback is not None:
                    retry_callback()

                models = self.get_primary(
                    Model,
                    n,
                    callback=callback,
                    retry_callback=retry_callback,
                    public=public,
                    deleted=deleted,
                    retry_count=retry_count + 1,
                    retry=True,
                )
                return models
            else:
                # self.tainted = True

                raise AssertionError(
                    f"Could not find test data for `{self.user.uuid}` table "
                    f"`{Model.__tablename__}` after `{retry_count}` "
                    "randomizations. Offending query:\n"
                    f"{util.sql_render(self.session, q)}"
                )

        if deleted is not None:
            logger.debug("Checking deleted.")
            assert all(mm.deleted is deleted for mm in models)

        if public is not None:
            logger.debug("Checking public.")
            assert all(mm.public is public for mm in models)
        return models  # type: ignore

    def get_users(
        self,
        n: int,
        get_primary_kwargs: GetPrimaryKwargs = GetPrimaryKwargs(),
        *,
        other: bool = False,
    ) -> Tuple[User, ...]:
        callback = None
        if other:
            callback = lambda q: q.where(User.id != self.user.id)

        return self.get_primary(
            User,
            n,
            callback=callback,
            **get_primary_kwargs,
        )

    def get_users_data(
        self,
        n: int | None = None,
        get_primary_kwargs: GetPrimaryKwargs = GetPrimaryKwargs(),
        *,
        other: bool = False,
    ) -> Data[ResolvedUser]:
        return self.get_data_primary(User, n, get_primary_kwargs, other=other)

    # ----------------------------------------------------------------------- #

    def get_documents_retry_callback(self):
        logger.debug("Calling `get_collections_retry_callback`.")
        self.randomize_grants()
        # self.mk(
        #     create_documents_unique=False,
        #     create_grants=dict(exclude_grants_self=True),
        # )
        self.session.commit()  # NOTE: It might look stupid to do this but it works.

    def get_documents(
        self,
        n: int,
        get_primary_kwargs: GetPrimaryKwargs = GetPrimaryKwargs(),
        *,
        level: Level | None = None,
        other: bool | None = False,
        **kwargs,
    ) -> Tuple[Document, ...]:
        """Gets user documents by default.

        When :param:`other` is ``None``, the ownership of documents should be
        treated arbitrarily.
        """

        if get_primary_kwargs.get("deleted"):
            kwargs["exclude_deleted"] = False

        def callback(q):
            if other is None:
                ...
            elif not other:
                assert level is not None, "Level is required when `other` is `False`."
                conds = self.user.q_conds_grants(level=level, **kwargs)
                q = q.join(Grant).where(*conds)
            else:
                q_has_grants = (
                    select(Grant.id_document)
                    .where(Grant.id_user == self.user.id)
                    .group_by(Grant.id_document)
                    .having(func.count(Grant.uuid) > 0)
                )
                q = q.where(Document.id.not_in(q_has_grants))

            return q

        return self.get_primary(
            Document,
            n,
            callback=callback,
            retry_callback=self.get_documents_retry_callback,
            **get_primary_kwargs,
        )

    def get_documents_data_callback(
        self,
        data_raw: Dict[str, Any],
        data_items: Tuple[Document, ...],
    ) -> None:
        uuid_documents = uuids(data_items)
        q_grants = (
            select(Grant)
            .join(Document)
            .where(Document.uuid.in_(uuid_documents), Grant.id_user == self.user.id)
        )
        data_raw["grants"] = {
            gg.uuid_document: gg for gg in self.session.scalars(q_grants)
        }
        data_raw["token_user_grants"] = data_raw["grants"]
        data_raw["uuids"] = uuid_documents

    def get_documents_data(
        self,
        n: int | None = None,
        get_primary_kwargs: GetPrimaryKwargs = GetPrimaryKwargs(),
        *,
        other: bool = False,
        **kwargs,
    ) -> Data[ResolvedDocument]:
        return self.get_data_primary(
            Document,
            n,
            get_primary_kwargs,
            other=other,
            callback=self.get_documents_data_callback,
            **kwargs,
        )

    # ----------------------------------------------------------------------- #

    def get_collections_retry_callback(self):
        logger.debug("Calling `get_collections_retry_callback`.")
        self.mk(
            create_documents_unique=False,
            create_grants=dict(exclude_grants_self=True),
        )
        self.session.commit()  # NOTE: It might look stupid but it works.

    def get_collections(
        self,
        n: int,
        get_primary_kwargs: GetPrimaryKwargs = GetPrimaryKwargs(),
        other: bool | None = False,
        order_by_document_count: bool = True,
    ) -> Tuple[Collection, ...]:
        def callback(q):
            match other:
                case True:
                    cond_other = Collection.id_user != self.user.id
                case False:
                    cond_other = Collection.id_user == self.user.id
                case _:
                    cond_other = true()

            if order_by_document_count:
                q_ids = (
                    select(Collection.id.label("id_collection"))
                    .join(Assignment)
                    .group_by(Collection.id)
                    .having(func.count(Assignment.id_document) > 0)
                    .where(cond_other)
                    .order_by(desc(func.count(Assignment.id_document)))
                )
                q = q.where(Collection.id.in_(q_ids))

            return q

        return self.get_primary(
            Collection,
            n,
            callback=callback,
            retry_callback=self.get_collections_retry_callback,
            **get_primary_kwargs,
        )

    def get_collections_data(
        self,
        n: int | None = None,
        get_primary_kwargs: GetPrimaryKwargs = GetPrimaryKwargs(),
        *,
        other: bool = False,
    ) -> Data[ResolvedUser]:
        return self.get_data_primary(Collection, n, get_primary_kwargs, other=other)

    # ----------------------------------------------------------------------- #

    def get_document_grant(self, document: Document) -> Grant:
        grant = self.session.scalar(
            select(Grant).where(
                Grant.id_document == document.id, Grant.id_user == self.user.id
            )
        )
        if grant is None:
            raise AssertionError("Grant should have been created for document.")
        return grant

    def get_events(
        self,
        n: int,
        get_primary_kwargs: GetPrimaryKwargs = GetPrimaryKwargs(),
        other: bool | None = False,
        uuid_obj: str | None = None,
        kind_obj: KindObject | None = None,
        kind: KindEvent | None = None,
    ) -> Tuple[Event, ...]:
        """It is possible that a user has no events. To generate events,
        do something with the dummy first.
        """

        def callback(q):
            if other is None:
                ...
            elif not other:
                q = q.where(Event.uuid_user == self.user.uuid)
            else:
                q = q.where(Event.uuid_user != self.user.uuid)

            if kind_obj is not None:
                q = q.where(Event.kind_obj == kind_obj)
            if kind is not None:
                q = q.where(Event.kind == kind)
            if uuid_obj is not None:
                q = q.where(Event.uuid_obj == uuid_obj)

            return q

        if "retry" not in get_primary_kwargs:
            get_primary_kwargs.update(retry=False)
        if "allow_empty" not in get_primary_kwargs:
            get_primary_kwargs.update(allow_empty=True)

        return self.get_primary(Event, n, callback=callback, **get_primary_kwargs)

    def get(
        self,
        Model: ResolvableModel,
        n: int,
        get_primary_kwargs: GetPrimaryKwargs = GetPrimaryKwargs(),
        *,
        other: bool = False,
        **kwargs,
    ) -> Tuple[T_ResolvedPrimary, ...]:
        """This exists because :meth:`get_primary` will not include all of the nice
        callbacks and keywords.

        Intended for generic cases, like :meth:`data_primary`.
        """
        match (resolve_model(Model)).__kind__:
            case KindObject.user:
                meth = self.get_users
            case KindObject.document:
                meth = self.get_documents
            case KindObject.collection:
                meth = self.get_collections
            case KindObject.event:
                meth = self.get_events
            case bad:
                raise ValueError(f"Cannot construct data of kind `{bad.name}`.")

        return meth(n, get_primary_kwargs, other=other, **kwargs)  # type: ignore

    def get_data_primary(
        self,
        Model: ResolvableModel,
        n: int | None = None,
        get_primary_kwargs: GetPrimaryKwargs = GetPrimaryKwargs(),
        *,
        other: bool = False,
        callback: Callable[[Dict[str, Any], Tuple[Any, ...]], None] | None = None,
        **kwargs,
    ):
        model = resolve_model(Model)
        data_primary = self.get(
            model,
            n if n is not None else randint(5, 15),
            get_primary_kwargs,
            other=other,
            **kwargs,
        )

        ResolvedModel = BaseResolvedPrimary.get(model.__kind__)
        data = {ResolvedModel._attr_name_targets: data_primary}
        if callback is not None:
            callback(data, data_primary)

        return mwargs(
            Data,
            data=ResolvedModel.model_validate(data),
        )

    def get_data_grant_document(
        self,
        # get_kwargs_document: Dict[str, Any] = dict(level=Level.own),
        get_kwargs_users: Dict[str, Any] = dict(),
        n: int | None = None,
    ):
        # NOTE: Document must be owned by :attr:`user`.
        def callback(raw: Dict[str, Any]) -> None:
            raw["token_user_grants"] = {
                self.user.uuid: self.get_document_grant(raw["document"]),
            }

        return self.get_data_secondary(
            Document,
            User,
            # get_kwargs_target=get_kwargs_document,
            source=self.get_documents(1, level=Level.own)[0],
            get_kwargs_target=get_kwargs_users,
            callback=callback,
            n=n,
        )

    def get_data_grant_user(
        self,
        get_kwargs_document: Dict[str, Any] = dict(other=None),
        n: int | None = None,
    ):
        # NOTE: For now, ``token_user_grants`` are the same as grants. This
        #       will change when admin mode is added.
        def callback(raw: Dict[str, Any]) -> None:
            raw["token_user_grants"] = raw["grants"]

        return self.get_data_secondary(
            User,
            Document,
            source=self.user,
            get_kwargs_target=get_kwargs_document,
            callback=callback,
            n=n,
        )

    def get_data_assignment_collection(
        self,
        get_kwargs_document: Dict[str, Any] = dict(other=None),
        collection: Collection | None = None,
        n: int | None = None,
    ):
        if collection is None:
            (collection,) = self.get_collections(1)

        return self.get_data_secondary(
            Collection,
            Document,
            source=collection,
            get_kwargs_target=get_kwargs_document,
            n=n,
        )

    def get_data_assignment_document(
        self,
        get_kwargs_collection: Dict[str, Any] = dict(other=None),
        document: Document | None = None,
        n: int | None = None,
    ):
        if document is None:
            (document,) = self.get_documents(1, level=Level.own)

        return self.get_data_secondary(
            Document,
            Collection,
            source=document,
            get_kwargs_target=get_kwargs_collection,
            n=n,
        )

    def get_data_secondary(
        self,
        ModelSource: ResolvableModel,
        ModelTarget: ResolvableModel,
        n: int | None = None,
        *,
        get_kwargs_source: Dict[str, Any] = dict(),
        get_kwargs_target: Dict[str, Any] = dict(),
        source: Annotated[
            Any,
            Doc("Use this to inject a source directly."),
        ] = None,
        callback: Callable[[Dict[str, Any]], None] | None = None,
    ):
        model_source = resolve_model(ModelSource)
        model_target = resolve_model(ModelTarget)
        Resolved = BaseResolved.get((model_source.__kind__, model_target.__kind__))
        assert issubclass(Resolved, BaseResolvedSecondary)

        if source is not None:
            if not isinstance(source, model_source):
                msg = f"`{source}` should be an instance of `{model_source}`."
                raise AssertionError(msg)
        else:
            (source,) = self.get(model_source, 1, **get_kwargs_source)

        n = randint(5, 15) if n is None else n
        targets = self.get(model_target, n, **get_kwargs_target)

        # NOTE: Get assocs. Assocs are always labeled by their
        model_assoc = resolve_model(Resolved.kind_assoc)  # type: ignore
        id_source_name = f"id_{Resolved._attr_name_source}"
        uuid_target_name = f"uuid_{Resolved.kind_target.name}"

        q = (
            select(model_assoc)
            .join(model_target)
            .where(
                getattr(model_assoc, id_source_name) == source.id,
                model_target.uuid.in_(uuid_target := uuids(targets)),
            )
        )
        assocs = {
            getattr(assoc, uuid_target_name): assoc for assoc in self.session.scalars(q)
        }

        # NOTE: Callback should add any additional fields. This is why this
        #       function is not often called directly.
        data = {
            Resolved._attr_name_assoc: assocs,
            Resolved._attr_name_source: source,
            Resolved._attr_name_target: targets,
            f"uuid_{Resolved._attr_name_target}": uuid_target,
        }
        if callback is not None:
            callback(data)

        return mwargs(
            Data,
            data=Resolved.model_validate(data),
        )

    # # NOTE: `User` will always be the the same as
    # def data(self, kind: KindData) -> Data:
    #     logger.debug("Constructing dummy `Data` for kind `%s`.", kind.name)
    #     ...

    @property
    def token(self) -> Token:
        return Token(
            uuid=self.user.uuid,
            tier=(
                TokenPermissionTier.paid
                if not self.user.admin
                else TokenPermissionTier.admin
            ),
            read=[],
        )

    @property
    def token_encoded(self) -> str:
        return self.token.encode(self.auth)

    def access(self, *, method: HTTPMethod = HTTPMethod.GET) -> Access:
        return Access(self.session, self.token, method)

    def delete(
        self,
        *,
        api_origin: str,
        force: bool = True,
        method: HTTPMethod = HTTPMethod.GET,
    ) -> Delete:
        return Delete(
            self.session,
            self.token,
            method,
            api_origin=api_origin,
            access=self.access(method=method),
            force=force,
        )

    def requests(self, client_config, client: httpx.AsyncClient) -> Requests:
        # NOTE: Build configuration and context for the requests client. This
        #       is approximately that which is used by the client.
        profile = mwargs(
            ProfileConfig, token=self.token_encoded, uuid_user=self.user.uuid
        )
        context = ContextData(
            config=self.client_config_cls(
                use=UseConfig(host="default", profile="default"),
                hosts=dict(default=client_config.host),
                profiles=dict(default=profile),
            ),
            console_handler=ConsoleHandler(output=Output.yaml),  # type: ignore
        )
        return Requests(context, client)

    def dispose(self):
        logger.debug("Disposing of dummy data for user `%s`.", self.user.uuid)
        session = self.session
        session.reset()

        user = session.scalar(select(User).where(User.uuid == self.user.uuid))
        if user is not None:
            session.delete(user)
            session.commit()


# =========================================================================== #
# YAML Provider


# NOTE: This loads the YAML assets when this module is invoked. It might be
#       helpful to implement some sort of laziness as the IO slows things down.
class DummyYAMLProviderInfoMeta(type):
    dummies_info: ClassVar[Dict[str, "DummyProviderYAMLInfo"]] = dict()
    dummies_file: str

    def __new__(cls, name, bases, namespace):
        if name == "DummyProviderYAMLInfo":
            return super().__new__(cls, name, bases, namespace)

        if (M := namespace.get("M")) is None:
            raise ValueError("`M` must be defined.")
        elif not issubclass(M, Base):
            raise ValueError(f"`{name}.M={M}` must be a subclass of `{Base}`.")

        # Dummies. Cannot declare dummies directly.
        if namespace.get("dummies") is not None:
            raise ValueError("Cannot specify dummies explicitly.")

        if (dummies_file := namespace.get("dummies_file")) is None:
            kind = KindObject._value2member_map_[M.__tablename__]
            dummies_file = util.Path.test_assets(f"{kind.name}.yaml")
            namespace["dummies_file"] = dummies_file

        T = super().__new__(cls, name, bases, namespace)
        cls.dummies_info[T.M.__tablename__] = T  # type: ignore
        return T

    @property
    def dummies(self) -> List[Dict[str, Any]]:
        logger.debug("Loading dummy data from `%s`.", self.dummies_file)

        with open(self.dummies_file, "r") as file:
            dummies = yaml.safe_load(file)

        _msg = f"`{self.__name__}.dummies_file={self.dummies_file}`"
        if not isinstance(dummies, list):
            raise ValueError(f"{_msg} must deserialize to a list.")
        elif len(
            bad := tuple(
                index
                for index, item in enumerate(dummies)
                if not isinstance(item, dict)
            )
        ):
            raise ValueError(f"{_msg} has bad entries in positions `{bad}`.")

        return dummies


class DummyProviderYAMLInfo(metaclass=DummyYAMLProviderInfoMeta):
    # NOTE: This will matter less when the dummy data project is copmlete.
    M: ClassVar[Type[Base]]
    dummies_file: ClassVar[str]
    dummies: ClassVar[List[Dict[str, Any]]]

    @classmethod
    def preload(cls, item):
        if hasattr(item, "content"):
            if item.content is not None and not isinstance(item.content, dict):
                raise ValueError(
                    "Content should be a `dict`, not a `type(item.content)`. "
                    f"`{item = }`."
                )
        return item

    @classmethod
    def merge(cls, session: Session):
        loaded = (cls.preload(cls.M(**item)) for item in cls.dummies)
        for item in loaded:
            session.merge(item)
        session.commit()


class DummyProviderYAML(BaseDummyProvider):
    dummy_yaml_info = [
        type(
            "DummyProviderYAMLUser",
            (DummyProviderYAMLInfo,),
            dict(M=User),
        ),
        type(
            "DummyProviderYAMLCollection",
            (DummyProviderYAMLInfo,),
            dict(M=Collection),
        ),
        type(
            "DummyProviderYAMLDocument",
            (DummyProviderYAMLInfo,),
            dict(M=Document),
        ),
        # type(
        #     "DummyProviderYAMLEdit",
        #     (DummyProviderYAMLInfo,),
        #     dict(M=Edit),
        # ),
        type(
            "DummyProviderYAMLGrant",
            (DummyProviderYAMLInfo,),
            dict(M=AssocUserDocument),
        ),
        type(
            "DummyProviderYAMLAssignment",
            (DummyProviderYAMLInfo,),
            dict(M=AssocCollectionDocument),
        ),
        type(
            "DummyProviderYAMLEvent",
            (DummyProviderYAMLInfo,),
            dict(M=Event),
        ),
    ]

    @classmethod
    def merge(cls, session: Session) -> None:
        logger.info("Merging YAML data into database.")
        # backwards = list(Base.metadata.sorted_tables)
        # backwards.reverse()
        for table in Base.metadata.sorted_tables:
            yaml_data = DummyProviderYAMLInfo.dummies_info.get(table.name)
            if yaml_data is None:
                continue

            yaml_data.merge(session)


# =========================================================================== #
# Default Provider


class DummyProvider(BaseDummyProvider):
    # config: ConfigSimulatus
    session: Session
    auth: Auth

    def __init__(
        self,
        config: ConfigSimulatus,
        session: Session,
        *,
        auth: Auth | None = None,
        use_existing: List[str] | User | None = None,
        client_config_cls: Type | None = None,
    ):
        self.config = config
        self.dummy = config.dummy

        self.auth = auth if auth is not None else Auth.forPyTest(config)
        self.session = session
        self.client_config_cls = client_config_cls or ClientConfig

        match use_existing:
            case list() as dummy_user_uuids:
                logger.info("Searching for existing dummy.")
                q_user = (
                    select(User)
                    .where(
                        # NOTE: Not too used already, not tainted.
                        func.JSON_LENGTH(User.content, "$.dummy.used_by")
                        < self.dummy.maximum_use_count,
                        func.JSON_VALUE(User.content, "$.dummy.tainted") == false(),
                        User.uuid.in_(dummy_user_uuids),
                        func.JSON_OVERLAPS(
                            '["YAML"]', func.JSON_VALUE(User.content, "$.tags")
                        )
                        != 1,
                        User.deleted == false(),
                    )
                    .order_by(func.random())
                    .limit(1)
                )
                user = session.scalar(q_user)
                if user is None:
                    logger.info("No suitable dummy found. Building a new dummy.")
                    self.user = self.mk_user()
                    self.mk()
                    return
                self.user = user
            case User() as user:
                logger.info("Using existing dummy with uuid `%s`.", user.uuid)
                self.user = user
            case _:
                logger.info("Building a new dummy.")
                self.user = self.mk_user()
                self.mk()

    def info_mark_used(self, test_fn: str) -> Self:
        logger.debug("Marking user `%s` as used by `%s`.", self.user.uuid, test_fn)
        session = self.session
        # NOTE: This should look like
        #
        #       .. code:: sql
        #
        #          UPDATE users SET info=JSON_ARRAY_APPEND(
        #            info, "$.dummy.used_by", "{test_fn}"
        #          ) WHERE uuid='000-000-000';
        #
        session.execute(
            update(User)
            .values(
                content=func.JSON_ARRAY_APPEND(User.content, "$.dummy.used_by", test_fn)
            )
            .where(User.uuid == self.user.uuid)
        )
        return self

    def info_mark_tainted(self, tainted: bool = True) -> Self:
        logger.debug("Marking user `%s` as tainted.", self.user.uuid)
        session = self.session
        session.execute(
            update(User)
            .values(content=func.JSON_REPLACE(User.content, "$.dummy.tainted", tainted))
            .where(User.uuid == self.user.uuid)
        )
        return self

    def info_is_tainted(self, maximum_use_count: int | None = None) -> bool | None:
        session = self.session
        if maximum_use_count is None:
            maximum_use_count = self.dummy.maximum_use_count

        # NOTE: Naming easter egg.
        a = func.JSON_LENGTH(User.content, "$.dummy.used_by") >= maximum_use_count
        b = func.JSON_VALUE(User.content, "$.dummy.tainted") > 0
        q = select(or_(a, b)).where(User.uuid == self.user.uuid)
        return session.scalar(q)

    # def check_health(self):
    #
    #     session, user = self.session, self.user
    #     n_collections = session.scalar(
    #         select(Collection).where(Collection.id_user == user.id)
    #     )
    #     if n_collections is None:
    #         self.mk_collections()
    #
    #     n_documents_create = session.scalar(
    #         select(Document)
    #         .join(Grant)
    #         .where(
    #             Grant.pending_from == PendingFrom.created,
    #             Grant.id_user == user.id,
    #         )
    #     )
    #     n_documents_shared = session.scalar(
    #         select(Document)
    #         .join(Grant)
    #         .where(Grant.pending_from != PendingFrom.created, Grant.id_user == user.id)
    #     )


# --------------------------------------------------------------------------- #


class DummyHandler:
    dummy: DummyConfig
    config: ConfigSimulatus
    sessionmaker: _sessionmaker[Session]
    auth: Auth
    user_uuids: List[str]

    def __init__(
        self,
        sessionmaker: _sessionmaker,
        config: ConfigSimulatus,
        user_uuids: List[str],
        *,
        auth: Auth | None = None,
    ):
        self.dummy = config.dummy
        self.config = config
        self.sessionmaker = sessionmaker
        self.auth = auth or Auth.forPyTest(config)
        self.user_uuids = user_uuids

    def q_clean(
        self,
        uuids: Set[str] | None = None,
        maximum_use_count: int | None = None,
    ):
        if maximum_use_count is None:
            maximum_use_count = self.dummy.maximum_use_count

        conds = list()
        if uuids is not None:
            conds.append(User.uuid.in_(uuids))

        return select(User).where(
            or_(
                func.JSON_LENGTH(User.content, "$.dummy.used_by") >= maximum_use_count,
                func.JSON_VALUE(User.content, "$.dummy.tainted"),
            ),
            *conds,
        )

    def dispose(
        self,
        uuids: Set[str] | None = None,
        maximum_use_count: int | None = None,
        note: str | None = None,
    ):
        note = note or "Generated by `dispose`."
        with self.sessionmaker() as session:
            logger.debug("Finding and removing tainted dummies.")
            q_bad = self.q_clean(maximum_use_count=maximum_use_count, uuids=uuids)
            for user in session.scalars(q_bad):
                dd = DummyProvider(self.config, session, use_existing=user)
                dd.dispose()

            session.execute(delete(User).where(User.deleted == true()))
            session.commit()

    def create_report(
        self,
        note: str,
    ):
        with self.sessionmaker() as session:
            reports = ReportController(session)
            report = reports.create_aggregate(note)
            session.add(report)
            session.commit()

    def restore(self) -> Self:
        with self.sessionmaker() as session:
            logger.debug("Getting current user count.")
            uuids_existing = list(session.scalars(select(User.id, User.uuid)))
            n_users = len(uuids_existing)
            assert n_users is not None

            dummies = self.dummy
            n_generate = dummies.minimum_count - n_users

            logger.debug("Generating `%s` dummies.", n_generate)
            while (n_generate := n_generate - 1) > 0:
                dd = DummyProvider(self.config, session, auth=self.auth)
                self.user_uuids.append(dd.user.uuid)
                n_generate -= 1

            q_user_uuids = select(User.uuid).where(User.id > dummies.minimum_user_id)
            user_uuids = list(session.scalars(q_user_uuids))
            self.user_uuids = user_uuids

        return self
