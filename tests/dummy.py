import secrets
from datetime import datetime
from http import HTTPMethod
from random import choice, randint, sample
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Dict,
    List,
    Self,
    Set,
    Tuple,
    Type,
    TypeVar,
)

import pytest
from app import __version__
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
)
from app.controllers.delete import Delete
from app.models import (
    LENGTH_CONTENT,
    LENGTH_DESCRIPTION,
    LENGTH_MESSAGE,
    LENGTH_NAME,
    LENGTH_TITLE,
    LENGTH_URL,
    Assignment,
    Base,
    Collection,
    Document,
    Event,
    Format,
    Grant,
    KindEvent,
    KindObject,
    Level,
    PendingFrom,
    Singular,
    T_Resolvable,
    Tables,
    User,
)
from app.schemas import mwargs
from faker import Faker
from faker.providers import internet
from sqlalchemy import Column, Select, func, inspect, select, update
from sqlalchemy.orm import Session

# https://faker.readthedocs.io/en/master/providers/faker.providers.internet.html
fkit = Faker()
item_kind_event: List[KindEvent] = list(KindEvent)
item_kind_obj: List[KindObject] = list(KindObject)
item_format: List[Format] = list(Format)
item_pending_from: List[PendingFrom] = list(PendingFrom)
item_level: List[Level] = list(Level)

NOW = int(datetime.timestamp(datetime.utcnow()))

fkit.add_provider(internet)
_Mk: Dict[str, Callable[[], Any]] = dict(
    kind=lambda: choice(item_kind_event),
    api_version=lambda: __version__,
    timestamp=lambda: randint(0, NOW),
    uuid=lambda: secrets.token_urlsafe(8),
    name=lambda: fkit.text(LENGTH_NAME),
    description=lambda: fkit.text(LENGTH_DESCRIPTION),
    detail=lambda: fkit.text(LENGTH_DESCRIPTION),
    url=lambda: fkit.url()[:LENGTH_URL],
    url_image=lambda: fkit.url()[:LENGTH_URL],
    level=lambda: Level(randint(1, 3)),
    pending_from=lambda: choice(item_pending_from),
    kind_obj=lambda: choice(item_kind_obj),
    kind_event=lambda: choice(item_kind_event),
    format=lambda: choice(item_format),
    content=lambda: bytes(fkit.text(LENGTH_CONTENT), "utf-8"),
    message=lambda: fkit.text(LENGTH_MESSAGE),
    admin=(mk_bool := lambda: bool(randint(0, 1))),
    deleted=mk_bool,
    public=mk_bool,
    pending=mk_bool,
    api_origin=lambda: "tests/dummy.py",
)


def get_mk(column: Column):

    if column.name.startswith("uuid"):
        return  # _Mk["uuid"]
    elif column.name.startswith("id"):
        return
    elif column.name.startswith("_prototype"):
        return

    match column:
        case Column(primary_key=True):
            return
        case _:
            return _Mk[column.name]  # type: ignore


from typing import Protocol

T_ResolvableContra = TypeVar(
    "T_ResolvableContra", Collection, User, Document, Grant, Event, covariant=True
)


class MkDummy(Protocol[T_ResolvableContra]):
    def __call__(self, **kwargs) -> T_ResolvableContra: ...


def create_mk_dummy(
    T_model: Type[T_ResolvableContra],
) -> MkDummy[T_ResolvableContra]:
    cols = {
        col.name: mk
        for col in inspect(T_model).columns
        if (mk := get_mk(col)) is not None
    }

    def wrapper(**kwargs) -> T_ResolvableContra:
        base_kwargs = {key: mk() for key, mk in cols.items()}
        base_kwargs.update(kwargs)
        return T_model(**base_kwargs)

    return wrapper


class Mk:

    user = staticmethod(create_mk_dummy(User))
    collection = staticmethod(create_mk_dummy(Collection))
    document = staticmethod(create_mk_dummy(Document))
    grant = staticmethod(create_mk_dummy(Grant))
    event = staticmethod(create_mk_dummy(Event))


# NOTE: I tried to avoid this but I'm sick of tests with annoying database
#       state problems and long setup. Use this chainable to expose data for
#       the user and set `private`/`deleted`ness here.
class Dummy:
    dummy_user_uuids: ClassVar[Set[str]] = set()
    dummy_kinds: ClassVar[Set[KindObject]] = {
        KindObject.user,
        KindObject.collection,
        KindObject.document,
        KindObject.grant,
        KindObject.assignment,
        KindObject.event,
    }

    auth: Auth
    session: Session
    user: User
    collections: Tuple[Collection, ...]
    documents: Tuple[Document, ...]
    grants: Tuple[Grant, ...]
    assignments: Tuple[Assignment, ...]
    events: Tuple[Event, ...]

    # ----------------------------------------------------------------------- #

    def __init__(self, auth: Auth, session: Session, user: User | None = None):
        self.auth = auth
        self.session = session
        if user is not None:
            self.find(user)
        else:
            self.build()

    def find(self, user: User):
        session = self.session
        self.user = user
        self.documents = tuple(session.scalars(user.q_select_documents()))
        self.collections = tuple(user.collections)
        self.grants = tuple(session.scalars(user.q_select_grants()))
        self.assignments = tuple(
            session.scalars(
                select(Assignment).where(
                    Assignment.id_collection.in_(
                        Collection.resolve_uuid(session, self.collections)
                    )
                )
            )
        )
        self.events = tuple(
            session.scalars(
                select(Event).where(Event.uuid_user == self.user.uuid).limit(10)
            )
        )

    def build(self):
        # NOTE: Create dummy users, documents, and collections. Grants and
        #       assignments will be made subsequently.
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
        self.dummy_user_uuids.add(user.uuid)

        for item in (user, *documents, *collections):
            session.refresh(item)

        # NOTE: Iter over collections first so that every document has a chance
        #       belong to each collection.
        session.add_all(
            assignments := tuple(
                Assignment(
                    id_document=document.id,
                    id_collection=collection.id,
                    deleted=False,
                )
                for collection in collections
                for document in documents
                if bool(randint(0, 3) % 3)
            )
        )
        self.assignments = assignments

        # NOTE: Create own grants. Additional grants will be created next.
        session.add_all(
            grants := tuple(
                Grant(
                    level=Level.own,
                    id_user=user.id,
                    id_document=document.id,
                    deleted=False,
                    pending=False,
                    pending_from=PendingFrom.created,
                )
                for document in documents
            )
        )
        self.grants = grants

        # NOTE: Add grants for documents of other users.
        q_id_user_max = select(func.max(User.id))
        id_user_max = session.scalar(q_id_user_max)
        if id_user_max is not None:
            id_users_shared = set(
                randint(1, id_user_max) for k in range(id_user_max) if not bool(k % 3)
            )
            q_grants_share = select(Grant).where(Grant.id_user.in_(id_users_shared))
            grants_share: Tuple[Grant, ...] = tuple(session.scalars(q_grants_share))
            grants_share_id_documents: Dict[int, Grant] = {
                grant_init.id_document: grant_init
                for grant_init in grants_share
                if grant_init.id_user != user.id
                and grant_init.uuid_document != "ex-parrot"
            }

            session.add_all(
                more_grants := tuple(
                    Grant(
                        uuid=secrets.token_urlsafe(8),
                        level=choice(list(Level)),
                        id_user=user.id,
                        id_document=grant_init.id_document,
                        uuid_parent=grant_init.uuid,
                        deleted=bool(randint(0, 1)),
                        pending=False,
                        pending_from=choice([PendingFrom.grantee, PendingFrom.granter]),
                    )
                    for id_document, grant_init in grants_share_id_documents.items()
                )
            )
            self.grants += more_grants

        self.events = tuple(Mk.event(uuid_user=user.uuid) for _ in range(10))
        session.add_all(self.events)
        session.commit()

        return user

    # ----------------------------------------------------------------------- #
    # Getters

    def get_document(self, level: Level) -> Document:

        if level is not None:
            q = self.user.q_select_documents(level=level)
        else:
            q = select(Document).where(Document.uuid == "ex-parrot")

        q = q.limit(1)
        doc = self.session.scalar(q)
        if doc is None:
            raise ValueError(f"Could not find document with level `{level}`.")

        return doc

    def get_grant(self, document) -> Grant:
        q = self.user.q_select_grants({document.uuid})
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

    # NOTE: `User` will always be the the same as
    def data(self, kind: KindData) -> Data:
        T_resolved: Type[BaseResolvedPrimary] | Type[BaseResolvedSecondary] = (
            BaseResolved.get(kind)
        )

        kwargs: Dict[str, Any]
        # if issubclass(T_resolved, BaseResolvedSecondary):
        #     ...
        # elif issubclass(T_resolved, BaseResolvedPrimary):

        if T_resolved.kind == KindData.user:
            kwargs = {"users": (self.user,)}
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
                msg = f"`Dummy` probably missing attribute named `{attr}`."
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

    # ----------------------------------------------------------------------- #

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
            msg = f"`Dummy.other` could not find a suitable `{kind.name}`."
            raise ValueError(msg)
        return res

    # ----------------------------------------------------------------------- #
    # Chainables and their helpers.

    def check_kinds(self, kinds: Set[KindObject]) -> ValueError | None:
        if bad := set(kind for kind in kinds if kind not in self.dummy_kinds):
            raise ValueError(f"Invalid kinds `{bad}`.")
        return None

    def visability(self, kinds: Set[KindObject], deleted: bool, public: bool) -> Self:
        if (err := self.check_kinds(kinds)) is not None:
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

        for items in (self.collections, self.documents, self.grants, self.assignments):
            for item in items:
                self.session.refresh(item)

        return self


@pytest.fixture
def dummy(auth: Auth, session: Session) -> Dummy:
    return Dummy(auth, session)


@pytest.fixture
def dummy_lazy(auth: Auth, session: Session) -> Dummy:
    if Dummy.dummy_user_uuids:
        uuid = choice(Dummy.dummy_user_uuids)
        _user = session.scalar(select(User).where(User.uuid == uuid))
        if _user is None:
            raise AssertionError(f"Somehow user `{uuid}` is `None`.")
        return Dummy(auth, session, user=_user)
    return Dummy(auth, session)
