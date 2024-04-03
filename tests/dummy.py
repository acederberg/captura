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
    NotRequired,
    Self,
    Set,
    Tuple,
    Type,
    TypedDict,
)

import httpx
from pydantic import SecretStr
from sqlalchemy import Select, false, func, select, true, update
from sqlalchemy.orm import Session

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
    T_ResolvedPrimary,
)
from app.controllers.delete import Delete
from app.fields import KindObject, Level, Plural, Singular
from app.models import (
    Assignment,
    Base,
    Collection,
    Document,
    Event,
    Grant,
    KindObject,
    Level,
    PendingFrom,
    Tables,
    User,
)
from app.schemas import mwargs
from client import ConsoleHandler, ContextData, Requests
from client.config import UseConfig
from client.flags import Output
from client.handlers import ConsoleHandler
from client.requests import Requests
from client.requests.base import ContextData
from tests.config import PytestClientConfig, PyTestClientProfileConfig
from tests.mk import Mk
from tests.test_models import ModelTestMeta

logger = util.get_logger(__name__)

# =========================================================================== #
# Providers


class GetPrimaryKwargs(TypedDict):
    public: NotRequired[bool | None]
    deleted: NotRequired[bool | None]


class BaseDummyProvider:
    dummy_kinds: ClassVar[Set[KindObject]] = {
        KindObject.user,
        KindObject.collection,
        KindObject.document,
        KindObject.grant,
        KindObject.assignment,
        KindObject.event,
    }

    session: Session

    user: User
    documents: Tuple[Document, ...]
    collections: Tuple[Collection, ...]

    # ----------------------------------------------------------------------- #
    # Getters

    def get_primary(
        self,
        Model_: Type[T_ResolvedPrimary] | KindObject,
        n: int,
        *,
        callback: Callable[[Any], Any] | None = None,
        public: bool | None = None,
        deleted: bool | None = None,
    ) -> Tuple[T_ResolvedPrimary, ...]:
        match Model_:
            case KindObject() as kind:
                Model = Tables[Plural[kind.name].value].value
            case _:
                Model = Model_

        if Model in (Grant, Assignment):
            raise ValueError()

        logger.debug("Getting data of kind `%s`.", Model.__tablename__)
        conds = list()
        if public is not None:
            bool_ = true() if public else false()
            conds.append(Model.public == bool_)
        if deleted is not None:
            bool_ = true() if deleted else false()
            conds.append(Model.deleted == bool_)

        q = select(Model).where(*conds).order_by(func.random()).limit(n)
        if callback:
            q = callback(q)

        # NOTE: Move assertions here to avoid perflight checks in tests.
        models = tuple(self.session.scalars(q))
        assert len(models)
        if deleted is not None:
            print("Checking deleted...")
            for mm in models:
                print(mm.uuid, "->", mm.deleted)
            assert all(mm.deleted is deleted for mm in models)

        if public is not None:
            assert all(mm.public is public for mm in models)
        return models

    def get_users(
        self,
        n: int,
        kwargs_get_primary: GetPrimaryKwargs | None = None,
    ) -> Tuple[User, ...]:
        if kwargs_get_primary is None:
            kwargs_get_primary = {}
        return self.get_primary(User, n, **kwargs_get_primary)

    def get_documents(
        self,
        n: int,
        kwargs_get_primary: GetPrimaryKwargs | None = None,
    ) -> Tuple[Document, ...]:
        if kwargs_get_primary is None:
            kwargs_get_primary = {}
        return self.get_primary(Document, n, **kwargs_get_primary)

    def get_collections(
        self,
        n: int,
        kwargs_get_primary: GetPrimaryKwargs | None = None,
    ) -> Tuple[Collection, ...]:
        if kwargs_get_primary is None:
            kwargs_get_primary = {}
        return self.get_primary(Collection, n, **kwargs_get_primary)

    def get_user_documents(
        self, level: Level, deleted: bool | None = False, *, n: int = 1, **kwargs
    ) -> Tuple[Document, ...]:
        logger.debug("Getting user documents.")
        kwargs.update(exclude_deleted=not deleted)
        q = self.user.q_select_documents(level=level, **kwargs)
        if deleted is not None:
            bool_ = true() if deleted else false()
            q = q.where(Document.deleted == bool_)

        q = q.order_by(func.random()).limit(n)
        util.sql(self.session, q)
        docs = tuple(self.session.scalars(q))

        assert len(docs)
        if deleted is not None:
            assert all(dd.deleted is deleted for dd in docs)

        return docs

    def get_user_collections(self, n: int = 1, **kwargs) -> Tuple[Collection, ...]:
        logger.debug("Getting user collections.")
        q = Collection.q_select_for_user(
            self.user.uuid, kwargs.pop("uuids", None), **kwargs
        )
        q = q.order_by(func.random()).limit(n)
        collections = tuple(self.session.scalars(q))

        assert len(collections)
        if kwargs.get("exclude_deleted") in (True, None):
            assert all(cc.deleted is False for cc in collections)

        return collections

    def get_document_grant(self, document: Document, **kwargs) -> Grant:
        logger.debug("Getting user grants.")
        q = self.user.q_select_grants({document.uuid}, **kwargs)
        q = q.limit(1)
        grant = self.session.scalar(q)
        if grant is None:
            raise AssertionError("Grant should have been created for document.")
        return grant

    @property
    def token(self) -> Token:
        return Token(uuid=self.user.uuid, admin=self.user.admin, permissions=[])

    @property
    def token_encoded(self) -> str:
        return self.auth.encode(Token)

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
        profile = PyTestClientProfileConfig(
            token=self.auth.encode(
                dict(
                    uuid=self.user.uuid,
                    admin=self.user.admin,
                )
            ),
            uuid_user=self.user.uuid,
        )

        context = ContextData(
            config=PytestClientConfig(
                use=UseConfig(host="default", profile="default"),
                hosts=dict(default=client_config.host),
                profiles=dict(default=profile),
            ),
            console_handler=ConsoleHandler(output=Output.yaml),  # type: ignore
        )
        return Requests(context, client)

    # NOTE: `User` will always be the the same as
    def data(self, kind: KindData) -> Data:
        logger.debug("Constructing dummy `Data` for kind `%s`.", kind.name)

        T_resolved: Type[BaseResolvedPrimary] | Type[BaseResolvedSecondary]
        T_resolved = BaseResolved.get(kind)  # type: ignore

        kwargs: Dict[str, Any]

        if T_resolved.kind in {KindData.user}:
            kwargs = {"users": (self.user,)}
        elif T_resolved.kind in {KindData.grant_document, KindData.grant_user}:
            (document,) = self.get_user_documents(n=1, level=Level.own)
            grant = self.get_document_grant(document)

            if T_resolved.kind == KindData.grant_document:
                grants = {grant.uuid_user: grant}
                kwargs = dict(
                    document=document,
                    users=(self.user,),
                    grants=grants,
                    token_user_grants=grants,
                )
            else:
                grants = {grant.uuid_document: grant}
                kwargs = dict(
                    documents=(document,),
                    user=self.user,
                    grants=grants,
                    token_user_grants=grants,
                )
        elif T_resolved.kind in {
            KindData.collection,
            KindData.document,
            KindData.edit,
            KindData.event,
        }:
            assert issubclass(T_resolved, BaseResolvedPrimary)
            attr = T_resolved._attr_name_targets
            try:
                attr_value = getattr(self, attr)
            except AttributeError as err:
                msg = f"`DummyProvider` probably missing attribute named `{attr}`."
                raise AttributeError(msg) from err

            if T_resolved.kind == KindData.document:
                items = {aa.uuid: aa for aa in attr_value if randint(0, 2)}
                grants = {
                    gg.uuid_document: gg
                    for gg in self.grants
                    if gg.uuid_document not in items
                }
                kwargs = {
                    attr: tuple(items.values()),
                    "grants": grants,
                    "token_user_grants": grants,
                }
            elif T_resolved.kind == KindData.edit:
                items = {aa.document.uuid: aa for aa in attr_value if randint(0, 2)}
                kwargs = {
                    attr: tuple(items.values()),
                    "grants": {
                        gg.uuid_document: gg
                        for gg in self.grants
                        if gg.uuid_document in items
                    },
                }
            else:
                kwargs = {attr: tuple(aa for aa in attr_value if randint(0, 2))}
        else:
            raise ValueError(f"No implementation for data kind `{kind}`.")

        return mwargs(
            Data,
            data=mwargs(T_resolved, **kwargs),
            user_token=self.user,
        )

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

    def _visibility_check_kinds(self, kinds: Set[KindObject]) -> ValueError | None:
        if bad := set(kind for kind in kinds if kind not in self.dummy_kinds):
            raise ValueError(f"Invalid kinds `{bad}`.")
        return None

    def visability(self, kinds: Set[KindObject], deleted: bool, public: bool) -> Self:
        if (err := self._visibility_check_kinds(kinds)) is not None:
            raise err

        session = self.session
        for kind in kinds:
            T_Model = Tables[Singular(kind.name).name].value
            values = dict(deleted=deleted, public=public)
            if not hasattr(T_Model, "public"):
                values.pop("public")

            session.execute(update(T_Model).values(**values))

        session.commit()

        return self

    def refresh(self) -> Self:
        self.session.refresh(self.user)
        for items in (self.collections, self.documents):
            for item in items:
                self.session.refresh(item)

        return self

    def find(self, user: User):
        session = self.session

        self.user = user
        self.documents = tuple(session.scalars(user.q_select_documents()))
        self.collections = tuple(user.collections)


class DummyProviderYAML(BaseDummyProvider):
    def __init__(self, auth: Auth, session: Session, user: User):
        self.auth = auth
        self.session = session
        self.find(user)

    @classmethod
    def merge(cls, session: Session) -> None:
        logger.info("Merging YAML data into database.")
        backwards = list(Base.metadata.sorted_tables)
        backwards.reverse()
        for table in Base.metadata.sorted_tables:
            cls_model = ModelTestMeta.__children__.get(table.name)
            if cls_model is None:
                continue
            cls_model.merge(session)


class DummyProvider(BaseDummyProvider):
    dummy_user_uuids: ClassVar[list[str] | None] = None

    def __init__(self, auth: Auth, session: Session, use_existing: bool | User = False):
        self.auth = auth
        self.session = session

        if self.dummy_user_uuids is None:
            clsname = self.__class__.__name__
            raise AttributeError(
                f"Attribute `dummy_user_uuids` must be set before `{clsname}` "
                "is instantiated. This should be done in the `load_tables` "
                "fixture"
            )

        match use_existing:
            case True if len(self.dummy_user_uuids):
                logger.info("Using random existing dummy.")
                user = User.if_exists(session, choice(self.dummy_user_uuids))
                self.find(user)
            case User() as user:
                logger.info("Using existing dummy with uuid `%s`.", user.uuid)
                self.find(user)
            case _:
                logger.info("Building a new dummy.")
                self.build()

    def mk_assignments(self):
        # NOTE: Iter over collections first so that every document has a chance
        #       belong to each collection.
        self.session.add_all(
            assignments := tuple(
                Assignment(
                    id_document=document.id,
                    id_collection=collection.id,
                    deleted=False,
                )
                for collection in self.collections
                for document in self.documents
                if bool(randint(0, 3) % 3)
            )
        )
        return assignments

    def mk_grants(self):
        grants = tuple(
            Grant(
                level=Level.own,
                id_user=self.user.id,
                id_document=document.id,
                deleted=False,
                pending=False,
                pending_from=PendingFrom.created,
            )
            for document in self.documents
        )

        # NOTE: Add grants for documents of other users.
        q_id_user_max = select(func.max(User.id))
        id_user_max = self.session.scalar(q_id_user_max)
        if id_user_max is None:
            raise AssertionError("Expect a nonzero number of users.")

        id_users_shared = set(k for k in range(1, id_user_max) if not bool(k % 3))
        if self.user.id in id_users_shared:
            id_users_shared.remove(self.user.id)

        # print(id_user_max)

        # ------------------------------------------------------------------- #
        # For self.

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

        # ------------------------------------------------------------------- #
        # For others.

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
        # def uniq(gg):
        #     return set((grant.id_user, grant.id_document) for grant in gg)
        #
        #
        # print("=============================================================")
        #
        # print()
        # uniq_other = uniq(grants_other)
        # print(f"pairs other {len(grants_other)}")
        # print("unique pairs other: ", len(uniq_other))
        #
        # print()
        # uniq_self = uniq(grants_self)
        # print(f"pairs self {len(grants_self)}")
        # print("unique pairs self: ", len(uniq_self))
        #
        # print()
        # uniq_created = uniq(grants)
        # print(f"pairs created {len(grants)}")
        # print("unique pairs created: ", len(uniq_created))
        #
        # print()
        # print(f"{uniq_other & uniq_self = }")
        # print(f"{uniq_other & uniq_created = }")
        # print(f"{uniq_created & uniq_self = }")
        #
        # print()
        # print(len(uniq_other) + len(uniq_created) + len(uniq_self))
        # print(len(uniq_other | uniq_created | uniq_self))
        # print("=============================================================")

        return grants + grants_self + grants_other

    def build(self):
        # NOTE: Create dummy users, documents, and collections. Grants and
        #       assignments will be made subsequently.
        logger.debug("Building primary dummy entries.")
        session = self.session
        session.add(user := Mk.user())
        user.admin = False
        user.deleted = False
        self.user = user

        documents: Tuple[Document, ...]
        documents = tuple(Mk.document() for _ in range(randint(5, 15)))
        self.documents = documents

        collections: Tuple[Collection, ...]
        collections = tuple(Mk.collection(user=user) for _ in range(randint(5, 15)))
        self.collections = collections

        session.add_all(documents)
        session.add_all(collections)
        session.commit()

        for item in (user, *documents, *collections):
            session.refresh(item)

        logger.debug("Adding secondary dummy entries.")
        self.assignments = self.mk_assignments()
        session.add_all(self.assignments)

        # NOTE: Create own grants. Additional grants will be created next.
        self.grants = self.mk_grants()
        for gg in self.grants:
            self.session.merge(gg)
        self.session.commit()

        self.events = tuple(Mk.event(uuid_user=user.uuid) for _ in range(10))
        session.add_all(self.events)
        session.commit()

        self.dummy_user_uuids.append(user.uuid)
        return user
