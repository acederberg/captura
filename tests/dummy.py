# =========================================================================== #
from http.cookiejar import LWPCookieJar
import secrets
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import sessionmaker as _sessionmaker
from http import HTTPMethod
from random import choice, randint
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Dict,
    Iterable,
    List,
    NotRequired,
    Self,
    Set,
    Tuple,
    Type,
    TypedDict,
)

import httpx
from pydantic import SecretStr, condate
from sqlalchemy import (
    Select,
    and_,
    delete,
    desc,
    false,
    func,
    literal_column,
    or_,
    select,
    text,
    true,
    update,
)
from sqlalchemy.orm import Session, aliased
import yaml

# --------------------------------------------------------------------------- #
from app import util
from app.auth import Auth, Token
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
    resolve_kind_data,
)
from app.controllers.delete import Delete
from app.fields import KindEvent, KindObject, Level, Plural, Singular
from app.models import (
    AnyModelType,
    Assignment,
    AssocCollectionDocument,
    AssocUserDocument,
    Base,
    Collection,
    Document,
    Edit,
    Event,
    Grant,
    KindObject,
    Level,
    PendingFrom,
    ResolvableModel,
    ResolvedRawCollection,
    ResolvedRawDocument,
    Tables,
    User,
    resolve_model,
    uuids,
)
from app.schemas import mwargs
from client import ConsoleHandler, ContextData, Requests
from client.config import UseConfig
from client.flags import Output
from client.handlers import ConsoleHandler
from client.requests import Requests
from client.requests.base import ContextData
from tests.config import PytestClientConfig, PyTestClientProfileConfig, PytestConfig
from tests.mk import Mk

logger = util.get_logger(__name__)

# =========================================================================== #
# Providers


class GetPrimaryKwargs(TypedDict):
    public: NotRequired[bool | None]
    deleted: NotRequired[bool | None]
    uuids: NotRequired[Set[str] | None]
    retry: NotRequired[bool]
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

    # tainted: bool = False  # NOTE: For fixtures.
    config: PytestConfig
    session: Session
    user: User
    auth: Auth

    def __init__(
        self,
        config: PytestConfig,
        session: Session,
        *,
        user: User,
        auth: Auth | None = None,
    ):
        self.config = config
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
        documents = tuple(Mk.document() for _ in range(randint(5, 15)))

        return documents

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
    ):
        # NOTE: Adding grants to the database can be a real pain in the ass
        #       because the primary key of the grants table is infact the
        #       ``uuid`` column and not the associated tables since the table
        #       is a tree. For this reason it is advised that a delete
        #       statement be emitted in addition to these queries.
        #
        # TLDR: Do not use ``session.merge``, just use ``DELETE`` or use
        #       options to avoid causing duplicate ``(id_user, id_document)``
        #       keys.
        logger.debug("Making grants...")
        grants = tuple(
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

        # NOTE: Add grants for documents of other users.
        id_users = self.session.scalars(select(User.id))
        id_users_shared = set(k for k in id_users if not bool(k % 3))
        if self.user.id in id_users_shared:
            id_users_shared.remove(self.user.id)

        # NOTE: Grants giving access to documents that exist already.
        if not exclude_grants_self:
            q_grants_share = select(Grant).where(Grant.id_user.in_(id_users_shared))
            grants_share_id_documents: Dict[int, Grant] = {
                grant_init.id_document: grant_init
                for grant_init in self.session.scalars(q_grants_share)
                if grant_init.id_user != self.user.id
            }
            grants_self = tuple(
                Grant(
                    uuid=secrets.token_urlsafe(8),
                    level=choice(list(Level)),
                    id_user=self.user.id,
                    id_document=grant_init.id_document,
                    uuid_parent=grant_init.uuid,
                    deleted=bool(randint(0, 1)),
                    pending=bool(randint(0, 2)),
                    pending_from=choice([PendingFrom.grantee, PendingFrom.granter]),
                )
                for grant_init in grants_share_id_documents.values()
            )
        else:
            grants_self = tuple()

        # NOTE: Grants to others on documents created.
        grants_other = tuple(
            Grant(
                uuid=secrets.token_urlsafe(8),
                level=choice(list(Level)),
                id_user=id_user,
                id_document=grant.id_document,
                uuid_parent=grant.uuid,
                deleted=bool(randint(0, 1)),
                pending=bool(randint(0, 2)),
                pending_from=choice([PendingFrom.grantee, PendingFrom.granter]),
            )
            for grant in grants
            for id_user in id_users_shared
            if randint(0, 2)
        )

        return grants + grants_self + grants_other

    def mk_collections(self) -> Tuple[Collection, ...]:
        logger.debug("Making collections...")
        return tuple(Mk.collection(user=self.user) for _ in range(randint(5, 15)))

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

        if documents is None:
            session.add_all(documents := self.mk_documents())
            session.commit()
            data.update(documents=set(dd.uuid for dd in documents))

        if collections is None:
            session.add_all(collections := self.mk_collections())
            session.commit()
            data.update(collections=set(dd.uuid for dd in collections))

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
            data.update(assignments=set(aa.uuid for aa in assignments))

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
            data.update(assignments=set(gg.uuid for gg in grants))

        # NOTE: Create some uniquely owned documents (important for tests of
        #       deltion cascading configuration). It is important to note
        #       that these documents are only gaurenteed to be unique when the
        #       dummy is the most recently generated.
        if create_documents_unique:
            documents_uniq = self.mk_documents()
            session.add_all(documents_uniq)
            session.commit()

    # ----------------------------------------------------------------------- #
    # Getters

    def randomize_primary(
        self,
        model: ResolvableModel,
        uuids: Set[str] | None = None,
    ) -> None:
        Model = resolve_model(model)
        # self.user.info["tags"].append(f"randomized-{Model.__tablename__}")

        q = update(Model).where(func.random() < 0.5)
        if uuids is not None:
            q = q.where(Model.uuid.in_(uuids))
        tuple(
            self.session.execute(q.values(deleted=deleted, public=public))
            for deleted in (0, 1)
            for public in (0, 1)
        )

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
            if retry and retry_count < 3:
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
                    "randomizations."
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
        self.mk(
            create_documents_unique=False,
            create_grants=dict(exclude_grants_self=True),
        )
        self.session.commit()  # NOTE: It might look stupid but it works.

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
    ) -> Tuple[Collection, ...]:
        def callback(q):
            match other:
                case True:
                    cond_other = Collection.id_user != self.user.id
                case False:
                    cond_other = Collection.id_user == self.user.id
                case _:
                    cond_other = true()

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
    ):
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

        return meth(n, get_primary_kwargs, other=other, **kwargs)

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
            n if n is not None else randint(1, 15),
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

    def get_data_secondary(
        self,
        ModelSource: ResolvableModel,
        ModelTarget: ResolvableModel,
        n: int | None = None,
        get_primary_kwargs_source: GetPrimaryKwargs = GetPrimaryKwargs(),
        get_primary_kwargs_target: GetPrimaryKwargs = GetPrimaryKwargs(),
        *,
        other_source: bool = False,
        other_target: bool = False,
        callback: Callable[[Dict[str, Any], Tuple[Any, ...]], None] | None = None,
    ):
        model_source = resolve_model(ModelSource)
        model_target = resolve_model(ModelTarget)
        Resolved = BaseResolved.get((model_source.__kind__, model_target.__kind__))
        assert issubclass(Resolved, BaseResolvedSecondary)

        (source,) = self.get(
            model_source, 1, get_primary_kwargs_source, other=other_source
        )
        n = randint(5, 15) if n is None else n
        targets = self.get(
            model_target, n, get_primary_kwargs_target, other=other_target
        )

        # NOTE: Get assocs. Assocs are always labeled by their
        model_assoc = resolve_model(Resolved.kind_assoc)  # type: ignore
        id_source_name = f"id_{Resolved._attr_name_source}"
        uuid_target_name = f"uuid_{Resolved.kind_target.name}"

        q = (
            select(model_assoc)
            .join(model_target)
            .where(getattr(model_assoc, id_source_name) == source.id)
        )
        assocs = {
            getattr(assoc, uuid_target_name): assoc for assoc in self.session.scalars(q)
        }

        data = {
            Resolved._attr_name_assoc: assocs,
            Resolved._attr_name_source: source,
            Resolved._attr_name_targets: targets,
        }

        return mwargs(
            Data,
            data=Resolved.model_validate(data),
        )

    # NOTE: `User` will always be the the same as
    def data(self, kind: KindData) -> Data:
        logger.debug("Constructing dummy `Data` for kind `%s`.", kind.name)
        ...

    @property
    def token(self) -> Token:
        return Token(uuid=self.user.uuid, admin=self.user.admin, permissions=[])

    @property
    def token_encoded(self) -> str:
        return self.auth.encode(self.token.model_dump())

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
        token = dict(uuid=self.user.uuid, admin=self.user.admin)
        _pf = dict(token=self.auth.encode(token), uuid_user=self.user.uuid)
        profile = PyTestClientProfileConfig.model_validate(_pf)

        context = ContextData(
            config=PytestClientConfig(
                use=UseConfig(host="default", profile="default"),
                hosts=dict(default=client_config.host),
                profiles=dict(default=profile),
            ),
            console_handler=ConsoleHandler(output=Output.yaml),  # type: ignore
        )
        return Requests(context, client)

    def other(
        self,
        kind: KindObject,
        *,
        callback: Annotated[
            Callable[[Select], Select] | None,
            "This should be used to add filters like `where` statements.",
        ] = None,
    ):
        match kind:
            case KindObject.event:
                q = select(Event).where(Event.uuid_user != self.user.uuid)
            case KindObject.document | KindObject.grant | KindObject.assignment:
                raise ValueError("`other` only supports `KindObject.event`.")
            case _:
                raise ValueError(f"Invalid value `{kind}` for `kind`.")

        if callback is not None:
            q = callback(q)

        q = q.limit(1)
        res = self.session.scalar(q)
        if res is None:
            msg = f"`DummyProvider.other` could not find a suitable `{kind.name}`."
            raise ValueError(msg)
        return res

    # ----------------------------------------------------------------------- #
    # Chainables and their helpers.

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
            item.content = bytes(item.content, "utf-8")
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
        type(
            "DummyProviderYAMLEdit",
            (DummyProviderYAMLInfo,),
            dict(M=Edit),
        ),
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
            "DummyProviderYAMLEdit",
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
            DummyProviderYAMLInfo.dummies_info[table.name].merge(session)


# =========================================================================== #
# Default Provider


class DummyProvider(BaseDummyProvider):
    session: Session
    auth: Auth

    def __init__(
        self,
        config: PytestConfig,
        session: Session,
        *,
        auth: Auth | None = None,
        use_existing: List[str] | User | None = None,
    ):
        self.config = config
        self.auth = auth if auth is not None else Auth.forPyTest(config)
        self.session = session
        match use_existing:
            case list() as dummy_user_uuids:
                logger.info("Using random existing dummy.")
                uuid = choice(dummy_user_uuids)
                user = User.if_exists(session, uuid)

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
            .values(info=func.JSON_ARRAY_APPEND(User.info, "$.dummy.used_by", test_fn))
            .where(User.uuid == self.user.uuid)
        )
        return self

    def info_mark_tainted(self, tainted: bool = True) -> Self:
        logger.debug("Marking user `%s` as tainted.", self.user.uuid)
        session = self.session
        session.execute(
            update(User)
            .values(info=func.JSON_REPLACE(User.info, "$.dummy.tainted", tainted))
            .where(User.uuid == self.user.uuid)
        )
        return self

    def info_is_tainted(self, maximum_use_count: int | None = None) -> bool | None:
        session = self.session
        if maximum_use_count is None:
            maximum_use_count = self.config.tests.dummies.maximum_use_count

        # NOTE: Naming easter egg.
        a = func.JSON_LENGTH(User.info, "$.dummy.used_by") >= maximum_use_count
        b = func.JSON_VALUE(User.info, "$.dummy.tainted") > 0
        q = select(or_(a, b)).where(User.uuid == self.user.uuid)
        return session.scalar(q)


# --------------------------------------------------------------------------- #


class DummyHandler:
    config: PytestConfig
    sessionmaker: _sessionmaker[Session]
    auth: Auth
    user_uuids: List[str]

    def __init__(
        self,
        sessionmaker: _sessionmaker,
        config: PytestConfig,
        user_uuids: List[str],
        *,
        auth: Auth | None = None,
    ):
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
            maximum_use_count = self.config.tests.dummies.maximum_use_count

        conds = list()
        if uuids is not None:
            conds.append(User.uuid.in_(uuids))

        return select(User).where(
            or_(
                func.JSON_LENGTH(User.info, "$.dummy.used_by") >= maximum_use_count,
                func.JSON_VALUE(User.info, "$.dummy.tainted"),
            ),
            *conds,
        )

    def dispose(
        self,
        uuids: Set[str] | None = None,
        maximum_use_count: int | None = None,
    ):
        with self.sessionmaker() as session:
            logger.debug("Finding and removing tainted dummies.")
            q_bad = self.q_clean(maximum_use_count=maximum_use_count, uuids=uuids)
            for user in session.scalars(q_bad):
                dd = DummyProvider(self.config, session, use_existing=user)
                dd.dispose()

    def restore(self) -> Self:
        with self.sessionmaker() as session:
            logger.debug("Getting current user count.")
            uuids_existing = list(session.scalars(select(User.id, User.uuid)))
            n_users = len(uuids_existing)
            assert n_users is not None

            dummies = self.config.tests.dummies
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
