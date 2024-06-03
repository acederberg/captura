# =========================================================================== #
import inspect
import secrets
from http import HTTPMethod  # type: ignore[attr-defined]
from typing import Any, ClassVar, Dict, Generator, NamedTuple, Set, Tuple, Type

import pytest
from fastapi import HTTPException
from pydantic import TypeAdapter
from sqlalchemy import false, func, select, update
from sqlalchemy.orm import Session, make_transient

# --------------------------------------------------------------------------- #
from app import util
from app.auth import Auth, Token
from app.controllers.access import Access, WithAccess, with_access
from app.controllers.base import (
    Data,
    KindData,
    ResolvedAssignmentCollection,
    ResolvedAssignmentDocument,
    ResolvedCollection,
    ResolvedDocument,
    ResolvedEvent,
    ResolvedGrantDocument,
    ResolvedGrantUser,
    ResolvedUser,
)
from app.err import (
    ErrAccessCollection,
    ErrAccessDocumentCannotRejectOwner,
    ErrAccessDocumentGrantBase,
    ErrAccessDocumentGrantInsufficient,
    ErrAccessDocumentPending,
    ErrAccessEvent,
    ErrAccessUser,
    ErrObjMinSchema,
)
from app.fields import LevelHTTP
from app.models import (
    Assignment,
    Collection,
    Document,
    Event,
    Grant,
    KindEvent,
    KindObject,
    Level,
    PendingFrom,
    User,
    UUIDSplit,
    uuids,
)
from dummy import DummyHandler, DummyProvider, DummyProviderYAML, GetPrimaryKwargs
from tests.test_controllers.util import check_exc, expect_exc, stringify

from ..conftest import COUNT

# Base

logger = util.get_logger(__name__)
httpcommon = (
    HTTPMethod.GET,
    HTTPMethod.POST,
    HTTPMethod.PUT,
    HTTPMethod.PATCH,
    HTTPMethod.DELETE,
)
methods_required = {
    "test_overloads",
    "test_modify",
    "test_deleted",
    "test_dne",
    "test_private",
    "test_d_fn",
}


# Checks that the required methods are included. Generates warnings when
class AccessTestMeta(type):
    fn_access_types: Dict[str, Type]
    allow_missing: bool = False

    def __new__(cls, name, bases, namespace):
        T = super().__new__(cls, name, bases, namespace)
        # NOTE: `allow_missing` and `BaseTestAccess` cases.
        if name == "BaseTestAccess":
            return T
        if not T.allow_missing:
            cls.check_missing(T)
        return T

    @classmethod
    def check_fn_access_types(cls, T):
        if (data := getattr(T, "fn_access_types", None)) is not None:
            msg = f"`{T.__name__}.fn_access_types` must be set."
            raise ValueError(msg)
        elif not isinstance(data, dict):
            msg = f"`{T.__name__}.fn_access_types` must be a dictionary."
            raise ValueError(msg)

    @classmethod
    def check_missing(cls, T):
        methods = {meth: getattr(T, meth, None) for meth in methods_required}
        name = T.__name__

        if bad := tuple(
            method_name for method_name, method in methods.items() if method is None
        ):
            msg = f"`{name}` missing methods `{bad}`."
            raise ValueError(msg)
        elif bad := tuple(
            method_name
            for method_name, method in methods.items()
            if not callable(method)
        ):
            msg = f"`{name}` has attributes `{bad}` that are not callable."
            raise ValueError(msg)


class BaseTestAccess(metaclass=AccessTestMeta):
    """Inherit from this to make sure that the required methods are defined on
    each class instance.

    Use the following template:

    .. code:: python
        class Test<Table>Access(BaseTestAccess):
            def test_private(self, dummy: DummyProvider): ...
            def test_modify(self, dummy: DummyProvider): ...
            def test_deleted(self, dummy: DummyProvider): ...
            def test_dne(self, dummy: DummyProvider): ...
            def test_overloads(self, dummy: DummyProvider): ...
            def test_d_fn(self, dummy: DummyProvider): ...
    """

    fn_access_ignored_params: ClassVar[Set[str]] = set()
    fn_access_types: ClassVar[Dict[str, Type]]
    allow_missing: ClassVar[bool] = False

    @pytest.fixture(scope="class")
    def dummy(
        self, dummy_handler: DummyHandler
    ) -> Generator[DummyProvider, None, None]:
        with dummy_handler.sessionmaker() as session:
            dummy = DummyProvider(dummy_handler.config, session)
            yield dummy

    def test_d_fn(self) -> None:
        # Check fn
        fn_access_types: Dict[str, Type] = self.fn_access_types
        match fn_access_types:
            case dict() as fn_access_types:
                if not len(fn_access_types):
                    raise AssertionError("`fn_access_name` must be non-empty.")
            case bad:
                clsname = self.__class__.__name__
                msg = f"`fn_access_name` should be defined for `{clsname}` "
                msg += "and must be a `tuple` of strings or a string (got "
                msg += f"type `{type(bad)}`)."
                raise AttributeError(msg)

        for fn_access_name, fn_access_T in fn_access_types.items():
            if (fn_access := getattr(Access, fn_access_name, None)) is None:
                msg = f"Failed to find method `{fn_access_name=}`."
                raise AssertionError(msg)
            elif not callable(fn_access):
                msg = f"`Access.{self.fn_access_name}` must be callable."
                raise AssertionError(msg)

            # Check fn access
            if (
                fn_access_data := getattr(
                    Access,
                    fn_access_data_name := f"d_{fn_access_name}",
                    None,
                )
            ) is None:
                msg = f"`Access.{fn_access_data_name}` should have a "
                msg += f"corresponding method `Access.{fn_access_data_name}`."
                raise AssertionError(msg)
            elif not callable(fn_access_data):
                msg = f"`Access.{fn_access_data_name}` must be callable. "
                msg += f"Got `{fn_access_data}`."
                raise AssertionError(msg)

            sig, sig_d = (
                inspect.signature(fn_access),
                inspect.signature(fn_access_data),
            )
            # Check params
            assert "return_data" in sig.parameters
            assert (
                "return_data" not in sig_d.parameters
            ), f"Expected signature of `{fn_access.__name__}` to not contain `return_data`."
            assert len(sig.parameters) > len(
                sig_d.parameters
            ), f"Too many parameters in `d_{fn_access}`."

            if missing_params := tuple(
                # print(
                #     "======================",
                #     f"{k=}",
                #     f"{k not in sig_d.parameters}",
                #     f"{k not in self.fn_access_ignored_params}",
                #     sep="\n",
                # )
                # or
                k
                for k, v in sig.parameters.items()
                if k not in sig_d.parameters
                and k != "return_data"
                and k not in self.fn_access_ignored_params
            ):
                msg = f"`Access.{fn_access_name}` missing parameters from "
                msg += f"`Access.{fn_access_data_name}`: {missing_params}"
                raise AssertionError(msg)
            elif params_bad := tuple(
                f"- `{k} -> {v} (expected {sig_d.parameters})`"
                for k, v in sig.parameters.items()
                if k != "return_data" and sig.parameters[k] == sig_d.parameters
            ):
                msg = f"`Access.{fn_access_name}` parameters annotations"
                msg += f"inconcistant with `Access.{fn_access_data_name}`: "
                msg += "\n".join(params_bad)
                raise AssertionError(msg)

            # Check returns
            assert sig_d.return_annotation == fn_access_T


# def split_uuid_collection(session: Session) -> UUIDSplit:
#     # Find collection ids to work with.
#     q = select(Collection.uuid)
#     quser = q.join(User).where(User.uuid == "000-000-000")
#     uuid_collection_user = set(session.execute(quser).scalars())
#
#     qother = q.where(Collection.uuid.not_in(uuid_collection_user))
#     uuid_collection_other = set(session.execute(qother).scalars())
#
#     assert len(uuid_collection_user), "Expected collections."
#     assert len(uuid_collection_other), "Expected collections."
#     return uuid_collection_user, uuid_collection_other
#
#
# def split_uuids_document(
#     session: Session,
#     level: Level,
# ) -> UUIDSplit:
#     # Find collection ids to work with.
#
#     q_n_total = select(func.count()).select_from(select(Document.uuid).subquery())
#     n_total = session.execute(q_n_total).scalar()
#
#     quser = (
#         select(Document.uuid)
#         .select_from(Document)
#         .join(Grant, onclause=Grant.id_document == Document.id)
#         .join(User, onclause=User.id == Grant.id_user)
#         .where(
#             User.uuid == "000-000-000",
#             Grant.level >= level.value,
#         )
#     )
#     uuid_granted = set(session.execute(quser).scalars())
#
#     qother = select(Document.uuid).where(Document.uuid.not_in(uuid_granted))
#     uuid_other = set(session.execute(qother).scalars())
#
#     if n_total != (n := len(uuid_granted)) + (m := len(uuid_other)):
#         raise AssertionError(
#             f"Expected a total of `{n_total}` results (got `{n + m}` "
#             f"entries, of which `{n}` belong to the user `000-000-000` "
#             f"and the  remaining `{m}` do not)."
#         )
#     elif len(bad := uuid_other & uuid_granted):
#         msg = "`uuid_other` and `uuid_granted` should not intersect."
#         msg += f"\n{uuid_other=},\n{uuid_granted=},\n{bad=}."
#         raise AssertionError(msg)
#     return uuid_granted, uuid_other


class AssignmentSplit(NamedTuple):
    collections: UUIDSplit
    documents: UUIDSplit


class GrantSplit(NamedTuple):
    users: UUIDSplit
    documents: UUIDSplit


def split_uuid_assignment(session: Session, level: Level) -> AssignmentSplit:
    return AssignmentSplit(
        collections=split_uuid_collection(session),
        documents=split_uuids_document(session, level),
    )


# =========================================================================== #
# Tests


class TestAccessUser(BaseTestAccess):
    # NOTE: Adapter is used to check that data has the correct generics so that
    #       `isinstance` checks do not require many lines.
    fn_access_types = dict(user=Data[ResolvedUser])
    adapter = TypeAdapter(Data[ResolvedUser])

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_overloads(self, dummy: DummyProvider, count):
        session = dummy.session
        access = dummy.access(method=HTTPMethod.GET)
        assert dummy.user.uuid == access.token_user.uuid
        assert access.token == dummy.token

        # NOTE: Input of a set results in output of a tuple.
        for n in range(1, 20, 2):
            users = dummy.get_users(n, GetPrimaryKwargs(deleted=False, public=True))
            N = len(users)

            assert all(uu.deleted is False for uu in users)
            uuid_user_set = User.resolve_uuid(session, users)

            res = access.user(uuid_user_set)
            assert isinstance(res, tuple)
            assert len(res) == N
            assert all(isinstance(user, User) for user in res)

            data = access.user(uuid_user_set, return_data=True)
            self.adapter.validate_python(data, from_attributes=True)
            assert data.data.users == res

        # NOTE: Singleton input -> Singleton output.
        res = access.user(dummy.user)
        assert isinstance(res, User)
        assert res.uuid == dummy.user.uuid

        data = access.user(dummy.user, return_data=True)
        self.adapter.validate_python(data, from_attributes=True)
        assert len(data.data.users) == 1
        assert data.data.users[0] == res

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_deleted(self, dummy: DummyProviderYAML, count):
        kwargs = GetPrimaryKwargs(deleted=True, public=True)
        (user_other,) = dummy.get_users(1, kwargs)
        access = dummy.access()

        if err := expect_exc(
            lambda: access.user(user_other.uuid),
            410,
            detail=ErrObjMinSchema(
                uuid_obj=user_other.uuid,
                kind_obj=KindObject.user,
                msg=ErrObjMinSchema._msg_deleted,
            ),
        ):
            raise err

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_modify(self, dummy: DummyProvider, count):
        # User should not be able to access another user for any method besides
        # httpx.GET

        (user_other,) = dummy.get_users(
            1, GetPrimaryKwargs(deleted=False, public=False), other=True
        )
        for meth in httpcommon:
            access = dummy.access(method=meth)
            assert access.token_user.uuid == dummy.user.uuid
            msg = (
                ErrAccessUser._msg_private
                if (exclude_public := (meth == HTTPMethod.GET))
                else ErrAccessUser._msg_modify
            )

            if err := expect_exc(
                lambda: access.user(
                    user_other.uuid,
                    exclude_public=exclude_public,
                ),
                403,
                detail=ErrAccessUser(
                    uuid_user_token=dummy.user.uuid,
                    uuid_user=user_other.uuid,
                    msg=msg,
                ),
            ):
                raise err

            # Success when accessing own user with patch.
            session = dummy.session
            dummy.user.deleted = False
            session.add(dummy.user)
            session.commit()
            session.expire(dummy.user)

            assert not dummy.user.deleted
            user_res = access.user(dummy.user.uuid)
            assert user_res.uuid == dummy.user.uuid
            assert access.token_user.uuid == dummy.user.uuid

        # NOTE: Changing the level to ``HTTPMethod.GET`` will make it such that
        #       calling for another public user does not fail.
        (user_other,) = dummy.get_users(1, GetPrimaryKwargs(deleted=False, public=True))
        access = dummy.access(method=HTTPMethod.GET)
        assert access.token_user.uuid == dummy.user.uuid

        user_res = access.user(user_other.uuid)
        assert user_res.uuid == user_other.uuid

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_private(self, dummy: DummyProvider, count):
        user = dummy.user
        (user_other,) = dummy.get_users(
            1, GetPrimaryKwargs(deleted=False, public=False)
        )

        for method in httpcommon:
            # NOTE: User can access self when private.
            access = dummy.access(method=method)
            user_res = access.user(user.uuid)
            assert (
                user.uuid
                == access.token_user.uuid
                == user_res.uuid
                == access.token_user.uuid
            )

            # NOTE: User cannot access other user that is private
            msg = (
                ErrAccessUser._msg_modify
                if method != HTTPMethod.GET
                else ErrAccessUser._msg_private
            )
            if err := expect_exc(
                lambda: access.user(user_other.uuid),
                403,
                uuid_user_token=user.uuid,
                uuid_user=user_other.uuid,
                msg=msg,
            ):
                raise err

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_dne(self, dummy: DummyProvider, count):
        for method in httpcommon:
            access = dummy.access(method=method)
            uuid_user = secrets.token_urlsafe(9)
            if err := expect_exc(
                lambda: access.user(uuid_user),
                404,
                detail=ErrObjMinSchema(
                    uuid_obj=uuid_user,
                    kind_obj=KindObject.user,
                    msg=ErrObjMinSchema._msg_dne,
                ),
            ):
                raise err


class TestAccessCollection(BaseTestAccess):
    fn_access_types = dict(collection=Data[ResolvedCollection])
    adapter = TypeAdapter(Data[ResolvedCollection])
    kind_data = KindData.collection

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_overloads(self, dummy: DummyProvider, count):
        session = dummy.session
        access = dummy.access(method=HTTPMethod.DELETE)

        # NOTE: Set in -> Tuple out
        for n in range(1, 21):
            collections = dummy.get_collections(n)
            uuid_collection = Collection.resolve_uuid(session, collections)
            N = len(collections)

            res = access.collection(uuid_collection)
            assert isinstance(res, tuple)
            assert len(res) == N
            assert all(isinstance(item, Collection) for item in res)
            assert Collection.resolve_uuid(session, res) == uuid_collection

            data_res = access.collection(uuid_collection, return_data=True)
            self.adapter.validate_python(data_res, from_attributes=True)
            assert data_res.kind == self.kind_data
            assert data_res.data.collections == res

        # NOTE: Singleton in, singleton out.
        (collection,) = dummy.get_collections(1)
        res = access.collection(collection.uuid)
        assert isinstance(res, Collection)
        assert res.uuid == collection.uuid

        data_res = access.collection(collection.uuid, return_data=True)
        self.adapter.validate_python(data_res, from_attributes=True)
        assert data_res.kind == self.kind_data
        assert isinstance(data_res.data, ResolvedCollection)

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_private(self, dummy: DummyProvider, count):
        (collection,) = dummy.get_collections(1)
        (collection_other,) = dummy.get_collections(1, other=True)
        assert collection_other.id_user != dummy.user.id

        collection.deleted, collection.public = False, False
        collection_other.deleted, collection_other.public = False, False

        session = dummy.session
        session.add(collection)
        session.add(collection_other)
        session.commit()
        session.expire(collection)
        session.expire(collection_other)

        for meth in httpcommon:
            # NOTE: User cannot access the private collections of others.
            access = dummy.access(method=meth)
            if err := expect_exc(
                lambda: access.collection(collection_other.uuid),
                403,
                detail=ErrAccessCollection(
                    msg=(
                        ErrAccessCollection._msg_private
                        if meth == HTTPMethod.GET
                        else ErrAccessCollection._msg_modify
                    ),
                    uuid_user_token=dummy.user.uuid,
                    uuid_collection=collection_other.uuid,
                ),
            ):
                raise err

            # NOTE: User can access their own private collection
            res = access.collection(collection.uuid)
            assert res.id_user == access.token_user.id
            assert collection.uuid == res.uuid

            # TODO: Private users cannot have public collections. How to resolve?

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_deleted(self, dummy: DummyProvider, count):
        get_primary_kwargs = GetPrimaryKwargs(deleted=True, public=True)
        (collection_other,) = dummy.get_collections(1, get_primary_kwargs, other=True)
        (collection,) = dummy.get_collections(1)
        collection_other.deleted, collection.deleted = True, True

        session = dummy.session
        session.add(collection)
        session.add(collection_other)
        session.commit()
        session.expire_all()

        for meth in httpcommon:
            # User cannot read own deleted collection
            access = dummy.access(method=meth)
            if err := expect_exc(
                lambda: access.collection(collection.uuid),
                410,
                detail=ErrObjMinSchema(
                    msg=ErrObjMinSchema._msg_deleted,
                    kind_obj=KindObject.collection,
                    uuid_obj=collection.uuid,
                ),
            ):
                raise err

            # NOTE: Lack of permission should not supercede deletion.
            if err := expect_exc(
                lambda: access.collection(collection_other.uuid),
                410,
                detail=ErrObjMinSchema(
                    msg=ErrObjMinSchema._msg_deleted,
                    kind_obj=KindObject.collection,
                    uuid_obj=collection_other.uuid,
                ),
            ):
                raise err

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_dne(self, dummy: DummyProvider, count):
        # NOTE: Id should not exist 100% bc default uses `token_urlsafe(8)`.
        uuid_obj = secrets.token_urlsafe(9)
        for method in httpcommon:
            access = dummy.access(method=method)
            if err := expect_exc(
                lambda: access.collection(uuid_obj),
                404,
                detail=ErrObjMinSchema(
                    msg=ErrObjMinSchema._msg_dne,
                    uuid_obj=uuid_obj,
                    kind_obj=KindObject.collection,
                ),
            ):
                raise err

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_modify(self, dummy: DummyProvider, count):
        (collection,) = dummy.get_collections(1)
        (collection_other,) = dummy.get_collections(1, other=True)

        for meth in httpcommon:
            access = dummy.access(method=meth)

            allow_public = meth != HTTPMethod.GET
            msg = ErrAccessCollection._msg_modify

            # Cannot access when not owner
            if err := expect_exc(
                lambda: access.collection(
                    collection_other.uuid,
                    allow_public=allow_public,
                ),
                403,
                detail=ErrAccessCollection(
                    msg=msg,
                    uuid_user_token=dummy.user.uuid,
                    uuid_collection=collection_other.uuid,
                ),
            ):
                raise err

            # Can when owner, impersonate owner.
            collection_res = access.collection(collection.uuid)
            assert collection_res.uuid == collection.uuid
            assert collection.id_user == dummy.user.id


class TestAccessDocument(BaseTestAccess):
    fn_access_types = dict(document=Data[ResolvedDocument])
    fn_access_ignored_params: ClassVar[Set[str]] = {"grants", "grants_index"}
    kind_data: ClassVar[KindData] = KindData.document
    adapter = TypeAdapter(Data[ResolvedDocument])

    def test_document_other(self, dummy: DummyProvider):
        for document in dummy.get_documents(25, other=True):
            n_grants = dummy.session.scalar(
                select(func.count(Grant.uuid)).where(
                    Grant.id_user == dummy.user.id,
                    Grant.id_document == document.id,
                )
            )
            assert not n_grants

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_overloads(self, dummy: DummyProvider, count):
        access = dummy.access(method=HTTPMethod.DELETE)

        for n in range(1, 25):
            documents = dummy.get_documents(level=Level.own, n=n)
            uuid_documents = Document.resolve_uuid(access.session, documents)

            documents_res = access.document(uuid_documents)
            assert isinstance(documents_res, tuple)
            assert len(documents_res) == (N := len(uuid_documents))
            assert all(isinstance(item, Document) for item in documents_res)

            data_res = access.document(uuid_documents, return_data=True)
            self.adapter.validate_python(data_res)
            assert len(data_res.data.documents) == N
            assert data_res.kind == self.kind_data

        (document,) = dummy.get_documents(level=Level.own, n=1)
        document_res = access.document(document.uuid)
        assert isinstance(document_res, Document)
        assert document_res.uuid == document.uuid

        data_res = access.document(document, return_data=True)
        self.adapter.validate_python(data_res)
        assert len(data_res.data.documents) == 1
        assert data_res.data.documents[0].uuid == document.uuid

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_private(self, dummy: DummyProvider, count):
        session = dummy.session
        user = dummy.user

        (document_other,) = dummy.get_documents(
            1,
            GetPrimaryKwargs(deleted=False, public=False),
            other=True,
        )
        (document,) = dummy.get_documents(level=Level.own, n=1)
        grant = dummy.get_document_grant(document)
        document.deleted = False
        grant.deleted = False

        session.add(grant)
        session.add(document)

        session.commit()
        session.expire_all()

        for method in httpcommon:
            # NOTE: Requires that grants exist. This does not overlap with
            #       `test_modify`.
            access = dummy.access(method=method)
            level = LevelHTTP[method.name].value
            level_next = None
            if level != Level.own:
                level_next = Level(level.value + 1)

            grant.level = level
            session.add(grant)
            session.commit()
            session.expire(grant)

            # NOTE: Can access documents when level is enough.
            document_res = access.document(document.uuid, level=level)
            assert document.uuid == document_res.uuid
            if level_next:
                # NOTE: Cannot access private documents of others without a
                #       grant.
                if err := expect_exc(
                    lambda: access.document(
                        document_other.uuid,
                        level=level_next,
                    ),
                    403,
                    uuid_user=user.uuid,
                    check_length=False,
                ):
                    raise err

            # NOTE: Cannot access private documents of others without a
            #       grant.
            if err := expect_exc(
                lambda: access.document(
                    document_other.uuid,
                    level=level_next,
                ),
                403,
                uuid_user=user.uuid,
                check_length=False,
            ):
                raise err

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_check_user_can_access(self, dummy: DummyProvider, count):
        # ------------------------------------------------------------------- #
        # Setup

        (document,) = dummy.get_documents(level=Level.view, n=1)
        user = dummy.user
        grant = dummy.get_document_grant(document)
        grant.deleted = False
        grant.pending = True
        grant.pending_from = PendingFrom.granter

        session = dummy.session
        session.add(grant)
        session.commit()
        session.expire_all()

        init_level = grant.level

        # ------------------------------------------------------------------- #
        # NOTE: Pending grant should not allow access on private doc

        httperr_pending = ErrAccessDocumentPending(
            msg=ErrAccessDocumentPending._msg_grant_pending,
            uuid_user=user.uuid,
            uuid_document=document.uuid,
            level_grant=grant.level,
            level_grant_required=Level.view,
            uuid_grant=grant.uuid,
            pending_from=PendingFrom.granter,
        )

        if err := expect_exc(
            lambda: user.check_can_access_document(document, Level.view),
            403,
            detail=httperr_pending,
        ):
            raise err

        # ------------------------------------------------------------------- #
        # NOTE: Changing the enum value should change the message returned.

        grant.pending_from = PendingFrom.grantee
        session.add(grant)
        session.commit()

        httperr_pending.pending_from = PendingFrom.grantee
        if err := expect_exc(
            lambda: user.check_can_access_document(document, Level.view),
            403,
            detail=httperr_pending,
        ):
            raise err

        # ------------------------------------------------------------------- #
        # NOTE: Using the `pending` keyword should negate the above warnings
        #       and populate `grants` with one grant.

        grants = dict()
        user.check_can_access_document(
            document,
            Level.view,
            grants_index="uuid_document",
            grants=grants,
            pending=True,
        )
        assert len(grants) == 1
        assert grant.uuid_document in grants
        assert grants[grant.uuid_document] == grant

        # ------------------------------------------------------------------- #
        # NOTE: Test orderedness

        grant.pending = False
        session.add(grant)
        session.commit()

        assert grant.uuid_document == document.uuid
        assert grant.uuid_user == user.uuid
        assert not grant.deleted

        for level, level_next in (
            (Level.view, Level.modify),
            (Level.modify, Level.own),
        ):
            # NOTE: Increment grant level.
            grant.level = Level(level)
            session.add(grant)
            session.commit()
            session.expire(grant)

            # NOTE: Level should be enough
            user.check_can_access_document(document, level)

            # Cover the case where level is `view` and want to check `own`.
            levels_above = [level_next]
            if level_next == Level.own:
                levels_above.append(Level.own)

            for level_above in levels_above:
                if err := expect_exc(
                    lambda: user.check_can_access_document(document, level_above),
                    403,
                    detail=ErrAccessDocumentGrantInsufficient(
                        msg=ErrAccessDocumentGrantInsufficient._msg_insufficient,
                        level_grant=level,
                        level_grant_required=level_above,
                        uuid_grant=grant.uuid,
                        uuid_user=user.uuid,
                        uuid_document=document.uuid,
                    ),
                ):
                    raise err

        # ------------------------------------------------------------------- #
        # NOTE: Deleting the grant should result in an error raised. Grant
        #       exists but is deleted state.

        grant.deleted = True
        session.add(grant)
        session.commit()

        if err := expect_exc(
            lambda: user.check_can_access_document(document, Level.view),
            410,
            detail=ErrAccessDocumentGrantBase(
                msg=ErrAccessDocumentGrantBase._msg_dne,
                level_grant_required=Level.view,
                uuid_user=user.uuid,
                uuid_document=document.uuid,
            ),
        ):
            raise err

        # --------------------------------------------------------------------#
        # NOTE: Using `exclude_deleted` should allow access when the grant is
        #       in a deleted state. The grants should be added to `grants`.

        grants = dict()
        user.check_can_access_document(
            document,
            Level.view,
            grants_index="uuid_user",
            grants=grants,
            exclude_deleted=False,
        )
        assert len(grants) == 1
        assert grant.uuid_user in grants
        assert grant == grants[grant.uuid_user]

        # ------------------------------------------------------------------- #
        # NOTE: Test no grant and respawn.

        session.delete(grant)
        session.commit()

        if err := expect_exc(
            lambda: user.check_can_access_document(document, Level.view),
            403,
            detail=ErrAccessDocumentGrantBase(
                uuid_user=user.uuid,
                uuid_document=document.uuid,
                msg=ErrAccessDocumentGrantBase._msg_dne,
                level_grant_required=Level.view,
            ),
        ):
            raise err

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_modify(self, dummy: DummyProvider, count):
        """Verify that a level of modify or less is required."""

        session, user = dummy.session, dummy.user
        (document,) = dummy.get_documents(level=Level.view, n=1)
        document.public = False
        session.add(document)

        grant = dummy.get_document_grant(document)
        grant.pending = False
        grant.deleted = False
        grant.level = Level.view
        session.add(grant)

        session.commit()

        # NOTE: Grant is insufficient for PUT, PATCH, DELETE
        for method in {HTTPMethod.PUT, HTTPMethod.PATCH, HTTPMethod.DELETE}:
            access = dummy.access(method=method)
            if err := expect_exc(
                lambda: access.document(document.uuid),
                403,
                check_length=False,
                uuid_user=user.uuid,
                msg=ErrAccessDocumentGrantInsufficient._msg_insufficient,
            ):
                raise err

        # NOTE: Grant is enough for read
        access = dummy.access(method=HTTPMethod.GET)
        _ = access.document(document.uuid)

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_deleted(self, dummy: DummyProvider, count):
        session, user = dummy.session, dummy.user
        (document,) = dummy.get_documents(1, level=Level.view)
        grant = dummy.get_document_grant(document)

        for method in httpcommon:
            access = dummy.access(method=method)
            level = LevelHTTP[method.name].value

            document.deleted = True
            grant.deleted = False
            session.add_all((grant, document))
            session.commit()
            session.expire_all()

            # NOTE: Document itself is deleted.
            if err := expect_exc(
                lambda: access.document(document.uuid),
                410,
                detail=ErrObjMinSchema(
                    msg=ErrObjMinSchema._msg_deleted,
                    uuid_obj=document.uuid,
                    kind_obj=KindObject.document,
                ),
            ):
                raise err

            document.deleted = False
            grant.deleted = True
            session.add_all((grant, document))
            session.commit()
            session.expire_all()

            # NOTE: No grant (i.e. hard deletion).
            if err := expect_exc(
                lambda: access.document(document.uuid),
                410,
                detail=ErrAccessDocumentGrantBase(
                    msg=ErrAccessDocumentGrantBase._msg_dne,
                    uuid_user=user.uuid,
                    uuid_document=document.uuid,
                    level_grant_required=level,
                ),
            ):
                raise err

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_dne(self, dummy: DummyProvider, count):
        uuid = secrets.token_urlsafe(9)
        for method in httpcommon:
            access = dummy.access(method=method)
            if err := expect_exc(
                lambda: access.document(uuid),
                404,
                detail=ErrObjMinSchema(
                    msg=ErrObjMinSchema._msg_dne,
                    kind_obj=KindObject.document,
                    uuid_obj=uuid,
                ),
            ):
                raise err


class TestAccessAssignment(BaseTestAccess):
    fn_access_types = dict(
        assignment_collection=Data[ResolvedAssignmentCollection],
        assignment_document=Data[ResolvedAssignmentDocument],
    )

    def test_overloads(self, dummy: DummyProvider):
        access = dummy.access(method=HTTPMethod.DELETE)

        def check_res(res, T_source_expected: Type, T_res_expected: Type):
            SS: Type
            TT: Type
            match res:
                case (Document(), tuple()):
                    SS, TT = Document, Collection
                    ss, tt = res
                case (Collection(), tuple()):
                    SS, TT = Collection, Document
                    ss, tt = res
                case Data(data=ResolvedAssignmentCollection() as data):
                    SS, TT = Collection, Document
                    ss, tt = data.collection, data.documents
                case Data(data=ResolvedAssignmentDocument() as data):
                    SS, TT = Document, Collection
                    ss, tt = data.document, data.collections
                case _:
                    raise ValueError("Results invalid.")

            assert isinstance(res, T_res_expected)
            assert SS == T_source_expected

            assert isinstance(ss, SS)

            assert isinstance(tt, tuple)
            assert len(tt) > 0
            assert all(isinstance(item, TT) for item in tt)

        # NOTE: For assignment document.
        (document,) = dummy.get_documents(1, level=Level.own)
        collections = dummy.get_collections(15)
        uuid_collection = Collection.resolve_uuid(dummy.session, collections)

        res = access.assignment_document(
            document.uuid,
            uuid_collection,
            validate_collections=False,
        )
        check_res(res, Document, tuple)

        res_data: Data = access.assignment_document(
            document.uuid,
            uuid_collection,
            validate_collections=False,
            return_data=True,
        )
        check_res(res_data, Document, Data)

        assert isinstance(res_data.data, ResolvedAssignmentDocument)
        assert res_data.data.document == res[0]
        assert res_data.data.collections == res[1]

        # NOTE: For assignment collection.
        (collection,) = dummy.get_collections(n=1)
        documents = dummy.get_documents(15, other=None)
        uuid_document = Document.resolve_uuid(dummy.session, documents)

        res = access.assignment_collection(
            collection.uuid,
            uuid_document,
            validate_documents=False,
        )
        check_res(res, Collection, tuple)

        res_data = access.assignment_collection(
            collection.uuid,
            uuid_document,
            return_data=True,
            validate_documents=False,
        )
        check_res(res_data, Collection, Data)

        assert isinstance(res_data.data, ResolvedAssignmentCollection)
        assert res_data.data.collection == res[0]
        assert res_data.data.documents == res[1]

    @pytest.mark.skip
    def test_private(self, dummy: DummyProvider):
        """The privacy status is not a factor in access. Should be invarient.

        See `test_access`.
        """
        ...

    @pytest.mark.skip
    def test_modify(self, dummy: DummyProvider):
        """^^^^^^^^^^^^^^^^^^^^^^^^"""
        ...

    def test_deleted(self, dummy: DummyProvider):
        (document,) = dummy.get_documents(1, level=Level.view)
        (collection,) = dummy.get_collections(1)

        (document_other,) = dummy.get_documents(1, other=True)
        (collection_other,) = dummy.get_collections(1, other=True)

        session = dummy.session
        document_other.deleted, document.deleted = True, True
        collection_other.deleted, collection.deleted = True, True
        session.add_all((document_other, document, collection_other, collection))
        session.commit()
        session.expire_all()

        # NOTE: Deletedness > permission.
        for method in httpcommon:
            if method == HTTPMethod.GET:
                continue

            access = dummy.access(method=method)
            for dd in (document, document_other):
                if err := expect_exc(
                    lambda: access.assignment_document(
                        dd.uuid,
                        {collection.uuid},
                        validate_collections=False,
                    ),
                    410,
                    detail=ErrObjMinSchema(
                        msg=ErrObjMinSchema._msg_deleted,
                        uuid_obj=dd.uuid,
                        kind_obj=KindObject.document,
                    ),
                ):
                    raise err

            for cc in (collection, collection_other):
                if err := expect_exc(
                    lambda: access.assignment_collection(
                        cc.uuid,
                        {document.uuid},
                        validate_documents=False,
                    ),
                    410,
                    detail=ErrObjMinSchema(
                        msg=ErrObjMinSchema._msg_deleted,
                        uuid_obj=cc.uuid,
                        kind_obj=KindObject.collection,
                    ),
                ):
                    raise err

    def test_dne(self, dummy: DummyProvider):
        uuid_bs = secrets.token_urlsafe(9)
        uuid_bs_set = {secrets.token_urlsafe(7) for _ in range(10)}

        for method in httpcommon:
            access = dummy.access(method=method)

            if err := expect_exc(
                lambda: access.assignment_collection(uuid_bs, uuid_bs_set),
                404,
                detail=ErrObjMinSchema(
                    msg=ErrObjMinSchema._msg_dne,
                    uuid_obj=uuid_bs,
                    kind_obj=KindObject.collection,
                ),
            ):
                raise err

            if err := expect_exc(
                lambda: access.assignment_document(uuid_bs, uuid_bs_set),
                404,
                msg=ErrObjMinSchema._msg_dne,
                uuid_obj=uuid_bs,
                kind_obj=KindObject.document,
            ):
                raise err


class TestAccessGrant(BaseTestAccess):
    fn_access_types = dict(
        grant_user=Data[ResolvedGrantUser],
        grant_document=Data[ResolvedGrantDocument],
    )
    kinds = {KindObject.user, KindObject.document, KindObject.grant}

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_self_access_only(self, dummy: DummyProvider, count):
        """For ``/grants/users/{uuid_user}`` only."""

        (user_other,) = dummy.get_users(1, other=True)
        (document,) = dummy.get_documents(
            1,
            other=False,
            level=Level.own,
            pending_from=PendingFrom.grantee,
        )

        # NOTE: Invariance with method
        for method in httpcommon:
            if method == HTTPMethod.GET:
                continue

            access = dummy.access(method=method)
            if err := expect_exc(
                lambda: access.grant_user(user_other.uuid, {document.uuid}),
                403,
                detail=ErrAccessUser(
                    msg=ErrAccessUser._msg_only_self,
                    uuid_user=user_other.uuid,
                    uuid_user_token=dummy.user.uuid,
                ),
            ):
                raise err

            access.grant_user(dummy.user.uuid, {document.uuid})

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_owner_access_only(self, dummy: DummyProvider, count):
        """For ``/grants/documents/{uuid_document}`` only."""

        def doit(access: Access, doc: Document):
            return access.grant_document(doc.uuid, {user.uuid})

        user = dummy.user
        (document_other,) = dummy.get_documents(
            1, GetPrimaryKwargs(deleted=False, public=True), other=True
        )
        assert not document_other.deleted
        (document,) = dummy.get_documents(level=Level.view, n=1)
        grant = dummy.get_document_grant(document)
        grant.deleted = False

        session = dummy.session
        httperr = ErrAccessDocumentGrantInsufficient(
            msg=ErrAccessDocumentGrantInsufficient._msg_insufficient,
            level_grant=Level.view,
            level_grant_required=Level.own,
            uuid_document=document.uuid,
            uuid_grant=grant.uuid,
            uuid_user=user.uuid,
        )

        # NOTE: Invariance with method
        for method in httpcommon:
            # NOTE: Cannot access other
            access = dummy.access(method=method)
            if err := expect_exc(
                lambda: doit(access, document_other),
                403,
                detail=ErrAccessDocumentGrantBase(
                    msg=ErrAccessDocumentGrantBase._msg_dne,
                    uuid_user=dummy.user.uuid,
                    uuid_document=document_other.uuid,
                    level_grant_required=Level.own,
                ),
            ):
                raise err

            # NOTE: Cannot access with only view.
            grant.level = Level.view
            httperr.level_grant = Level.view
            session.add(grant)
            session.commit()
            session.expire_all()

            if err := expect_exc(
                lambda: doit(access, document),
                403,
                detail=httperr,
            ):
                raise err

            # NOTE: Cannot access with only modify
            grant.level = Level.modify
            httperr.level_grant = Level.modify
            session.add(grant)
            session.commit()
            session.expire_all()

            if err := expect_exc(
                lambda: doit(access, document),
                403,
                detail=httperr,
            ):
                raise err

            # Can access with own
            grant.level = Level.own
            httperr.level_grant = Level.own
            if method == HTTPMethod.PATCH:
                grant.pending_from = PendingFrom.granter

            session.add(grant)
            session.commit()
            session.expire_all()

            doit(access, document)

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_overloads(self, dummy: DummyProvider, count):
        access = dummy.access()
        (document,) = dummy.get_documents(level=Level.own, n=1)

        res = access.grant_user(dummy.user, {document.uuid})
        assert len(res) == 2
        assert isinstance(res, tuple)

        uu, dd = res
        assert isinstance(uu, User)
        assert isinstance(dd, tuple)

        res = access.grant_user(dummy.user, {document.uuid}, return_data=True)
        assert isinstance(res, Data)
        assert isinstance(res.data, ResolvedGrantUser)

        # -------------------------------------------------------------------- #

        res = access.grant_document(document.uuid, {dummy.user.uuid})
        assert len(res) == 2
        assert isinstance(res, tuple)

        dd, uu = res
        assert isinstance(dd, Document)
        assert isinstance(uu, Tuple)

        res = access.grant_document(
            document.uuid,
            {dummy.user.uuid},
            return_data=True,
        )
        assert isinstance(res, Data)
        assert isinstance(res.data, ResolvedGrantDocument)

    @pytest.mark.skip
    def test_private(self, dummy: DummyProvider):
        """
        Why is this test empty?
        =======================================================================

        Please read the following.

        GET /grants/{kind_source}/{uuid_source}
        -----------------------------------------------------------------------

        The parameter ``uuid_target`` is used as a filter on results. It does
        not matter that the specified resources are private or public or not
        as

        1. Document owners should only be able to use these routes in the case
           where ``kind_source`` is ``document``.
        2. Users should only be able to access their own routes in the case
           where ``kind_source`` is ``user``.

        DELETE | POST | PATCH /grants/{kind_source}/{uuid_source}
        -----------------------------------------------------------------------

        The parameter ``uuid_target`` is used in ``POST`` requests to

        1. Select which users are to be invited to the ``document`` (
           ``kind_source='document'`` in this case).
        2. Select which documents a user wants to request access for.

        and for patch it respectively is used to approve or accept pending
        grants.

        Conclusion
        -----------------------------------------------------------------------

        It is not necessary to check anything pertaining to the ``target``
        parameter, only the source really.

        Further, since a user can only access their own grants with
        `/grants/users/{uuid_user}` private/public does not matter in this
        case.

        Finally, since only document owners can user
        `/grants/documents/{uuid_document}` this is not subject to any
        conditions concerning the ``public`` column.
        """
        ...

    @pytest.mark.skip
    def test_modify(self, dummy: DummyProvider):
        """See the note on `test_private`` about access.

        Tl;dr: Access is determined by the source. Thus this test is the same
               as the access rules for the source of the grants.
        """

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_deleted(self, dummy: DummyProvider, count):
        user = dummy.user
        kwargs = GetPrimaryKwargs(deleted=True, public=None)
        # (document_other,) = dummy.get_documents(1, kwargs, other=True)
        (document,) = dummy.get_documents(1, kwargs, level=Level.own)
        grant = dummy.get_document_grant(document)

        user.deleted = True
        grant.deleted = False
        grant.pending_from = PendingFrom.grantee
        session = dummy.session
        session.add(user)
        session.add(grant)
        session.commit()
        session.expire_all()

        assert user.deleted

        for method in httpcommon:
            # NOTE: Trying to access grants for deleted should fail with 410.
            access = dummy.access(method=method)
            print("-----------------------------------------")
            if err := expect_exc(
                lambda: access.grant_user(user.uuid, {document.uuid}),
                410,
                detail=ErrObjMinSchema(
                    msg=ErrObjMinSchema._msg_deleted,
                    uuid_obj=dummy.user.uuid,
                    kind_obj=KindObject.user,
                ),
            ):
                raise err

            if method == HTTPMethod.PATCH:
                continue

            # NOTE: Adding `exclude_deleted` should result in no errors raised.
            access.grant_user(user, {document.uuid}, exclude_deleted=False)

            # NOTE: Trying to access deleted documents with active user should
            #       raise a similar error.
            if err := expect_exc(
                lambda: access.grant_document(document.uuid, {user.uuid}),
                410,
                detail=ErrObjMinSchema(
                    msg=ErrObjMinSchema._msg_deleted,
                    kind_obj=KindObject.document,
                    uuid_obj=document.uuid,
                ),
            ):
                raise err

            # NOTE: Adding `exclude_deleted` should result in no erros raised.
            access.grant_user(dummy.user, (document,), exclude_deleted=False)

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_pending(self, dummy: DummyProvider, count):
        session = dummy.session
        user = dummy.user
        (document,) = dummy.get_documents(level=Level.own, n=1)
        grant = dummy.get_document_grant(document)

        user.deleted = False
        grant.level = Level.own
        session.add(user)
        session.add(grant)
        session.commit()
        session.expire(grant)
        session.expire(user)

        httperr = ErrAccessDocumentPending(
            msg=ErrAccessDocumentPending._msg_grant_pending,
            uuid_user=dummy.user.uuid,
            uuid_document=document.uuid,
            level_grant_required=Level.own,
            level_grant=grant.level,
            uuid_grant=grant.uuid,
            pending_from=PendingFrom.grantee,
        )

        for method in httpcommon:
            for pending_from in (PendingFrom.grantee, PendingFrom.granter):
                # NOTE: Should reject pending grants. It is important to note
                #       that the grants for a user on their own original
                #       documents will never be pending hence the mutations
                #       here.
                access = dummy.access(method=method)
                grant.pending = True
                grant.pending_from = pending_from
                session.add(grant)
                session.commit()
                session.expire_all()

                # documents should just be filtered when pending.
                httperr.pending_from = pending_from
                if method == HTTPMethod.PATCH:
                    continue

                if err := expect_exc(
                    lambda: access.grant_document(document, {dummy.user.uuid}),
                    403,
                    detail=httperr,
                ):
                    raise err

                if pending_from == PendingFrom.granter:
                    # NOTE: If ``exclude_pending`` is ``False`` the no error.
                    #       Document should not be filtered in the first case.
                    data = access.grant_user(
                        dummy.user, {document.uuid}, pending=True, return_data=True
                    )
                    assert data.kind == KindData.grant_user
                    assert data.data.documents, "Pending document filtered."
                else:
                    access.grant_document(document, {dummy.user.uuid}, pending=True)

                if method != HTTPMethod.POST:
                    _, documents = access.grant_user(dummy.user, {document.uuid})
                    assert not len(documents)

    @pytest.mark.parametrize(
        "dummy, count",
        [(None, k) for k in range(COUNT)],
        indirect=["dummy"],
    )
    def test_dne(self, dummy: DummyProvider, count):
        (document,) = dummy.get_documents(level=Level.own, n=1)
        grant = dummy.get_document_grant(document)
        assert grant.level == Level.own

        uuid_obj = secrets.token_urlsafe(8)
        errhttp = ErrObjMinSchema(
            msg=ErrObjMinSchema._msg_dne,
            uuid_obj=uuid_obj,
            kind_obj=KindObject.document,
        )

        for method in httpcommon:
            access = Access(dummy.session, dummy.token, method)

            # NOTE: Filters out documents that do not exist.
            f_user, f_document = access.grant_user(dummy.user, {uuid_obj})
            assert f_user == dummy.user
            assert len(f_document) == 0

            f_document, f_user = access.grant_document(document, {uuid_obj})
            assert f_document == document
            assert len(f_user) == 0

            # NOTE: Raises when source does not exist.
            errhttp.kind_obj = KindObject.document
            if err := expect_exc(
                lambda: access.grant_document(uuid_obj, {document.uuid}),
                404,
                detail=errhttp,
            ):
                raise err

            errhttp.kind_obj = KindObject.user
            if err := expect_exc(
                lambda: access.grant_user(uuid_obj, {dummy.user.uuid}),
                404,
                detail=errhttp,
            ):
                raise err


class TestAccessEvent(BaseTestAccess):
    fn_access_types = dict(event=Data[ResolvedEvent])
    kinds = {KindObject.event}

    def test_private(self):
        """The `private` column does not apply to events."""

        assert not hasattr(Event, "private")

    @pytest.mark.skip
    def test_modify(self, dummy: DummyProvider):
        """Access is invarient with respect to method. Modifying an event
        requires that the user own the event directly, which is the same
        requirement for read.
        """
        event_other = dummy.get_events(n=1, own=False)
        event = dummy.get_events(n=1, own=True)

        # NOTE: There is no public column!
        for method in httpcommon:
            access = dummy.access(method=method)

            data = access.event(event, return_data=True)
            assert isinstance(data, Data)
            assert isinstance(data.data, ResolvedEvent)
            assert len(data.data.events) == len(dummy.events)

            if err := expect_exc(
                lambda: access.event(event_other),
                403,
                detail=ErrAccessEvent(
                    msg="User cannot access event.",
                    uuid_event=event_other.uuid,
                    uuid_user_token=dummy.user.uuid,
                ),
            ):
                raise err

    @pytest.mark.skip
    def test_deleted(self, dummy: DummyProvider):
        event = dummy.events[0]

        for method in httpcommon:
            access = Access(dummy.session, dummy.token, method)

            if err := expect_exc(
                lambda: access.event(event),
                410,
                msg="Object is deleted.",
                uuid_obj=event.uuid,
                kind_obj="event",
            ):
                raise err

            # `exclude_deleted=False` should result in no error.
            access.event(event, exclude_deleted=False)

    def test_dne(self, dummy: DummyProvider):
        for method in httpcommon:
            access = Access(dummy.session, dummy.token, method)
            uuid_obj = secrets.token_urlsafe(8)
            if err := expect_exc(
                lambda: access.event(uuid_obj),
                404,
                detail=ErrObjMinSchema(
                    msg=ErrObjMinSchema._msg_dne,
                    uuid_obj=uuid_obj,
                    kind_obj=KindObject.event,
                ),
            ):
                raise err

    @pytest.mark.skip
    def test_overloads(self, dummy: DummyProvider):
        access = Access(dummy.session, dummy.token, HTTPMethod.GET)

        # NOTE: Putting in a uuid should return an event
        event = dummy.events[0]
        res = access.event(event.uuid)
        assert isinstance(res, Event)

        # NOTE: A set of uuids should return a tuple of events
        uuids = Event.resolve_uuid(dummy.session, dummy.events)
        res = access.event(uuids)
        assert isinstance(res, Tuple)
        assert all(isinstance(event, Event) for event in res)
        assert len(dummy.events) == len(res)

        # NOTE: ``return_data`` should result in the return type being `Data`.
        res = access.event(uuids, return_data=True)
        assert isinstance(res, Data)
        assert isinstance(res.data, ResolvedEvent)
        assert isinstance(res.data.events, Tuple)
        assert len(dummy.events) == len(res.data.events)


# @pytest.mark.skip
# def test_with_access(dummy: DummyProvider, auth: Auth):
#     """Test the intended functionality of `with_access`."""
#
#     class Barf(WithAccess):
#         @with_access(Access.d_user)
#         def user(self, data: Data) -> Data:
#             # Tack on an event when chained.
#             data.event = Event(
#                 **self.event_common,
#                 kind=KindEvent.update,
#                 kind_obj=KindObject.user,
#                 uuid_obj=data.data.user.uuid,
#             )
#             session.add(data.event)
#             session.commit()
#             session.refresh(data.event)
#
#             return data
#
#     b = Barf(
#         session,
#         {"uuid": "000-000-000"},
#         HTTPMethod.PATCH,
#         api_origin="tests",
#     )
#
#     assert b.access is not None
#     assert isinstance(b.access, Access)
#     assert callable(b.user)
#
#     data = b.user("000-000-000", resolve_user_token=b.token_user)
#     assert data.event is not None
#     assert data.event.uuid is not None
#
#     sig_access = inspect.signature(Access.d_user)
#     sig_barf = inspect.signature(Barf.user)
#
#     assert "return_data" not in sig_access.parameters
#     assert "return_data" not in sig_barf.parameters
#     assert len(sig_access.parameters) == len(sig_barf.parameters)
#     assert sig_barf.return_annotation == Data
#     assert b.access is not None
#     assert isinstance(b.access, Access)
#     assert callable(b.user)
#
#     data = b.user("000-000-000", resolve_user_token=b.token_user)
#     assert data.event is not None
#     assert data.event.uuid is not None
#
#     sig_access = inspect.signature(Access.d_user)
#     sig_barf = inspect.signature(Barf.user)
#
#     assert "return_data" not in sig_access.parameters
#     assert "return_data" not in sig_barf.parameters
#     assert len(sig_access.parameters) == len(sig_barf.parameters)
#     assert sig_barf.return_annotation == Data
