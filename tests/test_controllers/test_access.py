# =========================================================================== #
import inspect
import secrets
from http import HTTPMethod  # type: ignore[attr-defined]
from typing import Any, ClassVar, Dict, NamedTuple, Set, Tuple, Type

import pytest
from fastapi import HTTPException
from sqlalchemy import false, func, select, update
from sqlalchemy.orm import Session, make_transient

# --------------------------------------------------------------------------- #
from app import util
from app.auth import Auth, Token
from app.controllers.access import Access, WithAccess, with_access
from app.controllers.base import (
    Data,
    ResolvedAssignmentCollection,
    ResolvedAssignmentDocument,
    ResolvedCollection,
    ResolvedDocument,
    ResolvedEvent,
    ResolvedGrantDocument,
    ResolvedGrantUser,
    ResolvedUser,
)
from app.models import (
    Assignment,
    Collection,
    Document,
    Event,
    Grant,
    KindEvent,
    KindObject,
    Level,
    LevelHTTP,
    PendingFrom,
    User,
    UUIDSplit,
    uuids,
)
from tests.dummy import DummyProvider
from tests.test_controllers.util import check_exc, expect_exc, stringify

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
            def test_private(self, session: Session): ...
            def test_modify(self, session: Session): ...
            def test_deleted(self, session: Session): ...
            def test_dne(self, session: Session): ...
            def test_overloads(self, session: Session): ...
            def test_d_fn(self, session: Session): ...
    """

    fn_access_ignored_params: ClassVar[Set[str]] = set()
    fn_access_types: ClassVar[Dict[str, Type]]
    allow_missing: ClassVar[bool] = False

    @pytest.fixture(autouse=True, scope="session")
    def fixtures(self, load_tables) -> None:
        return

    def create_access(
        self,
        session,
        method: HTTPMethod = HTTPMethod.GET,
        uuid: str = "000-000-000",
    ) -> Access:
        token = Token(uuid=uuid, permissions=[])
        return Access(session, token, method)

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
            assert len(sig.parameters) > len(sig_d.parameters)
            assert "return_data" in sig.parameters
            assert (
                "return_data" not in sig_d.parameters
            ), f"Expected signature of `{fn_access}` to not contain `return_data`."

            print(self.fn_access_ignored_params)
            if missing_params := tuple(
                print(
                    "======================",
                    f"{k=}",
                    f"{k not in sig_d.parameters}",
                    f"{k not in self.fn_access_ignored_params}",
                    sep="\n",
                )
                or k
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


def split_uuid_collection(session: Session) -> UUIDSplit:
    # Find collection ids to work with.
    q = select(Collection.uuid)
    quser = q.join(User).where(User.uuid == "000-000-000")
    uuid_collection_user = set(session.execute(quser).scalars())

    qother = q.where(Collection.uuid.not_in(uuid_collection_user))
    uuid_collection_other = set(session.execute(qother).scalars())

    assert len(uuid_collection_user), "Expected collections."
    assert len(uuid_collection_other), "Expected collections."
    return uuid_collection_user, uuid_collection_other


def split_uuids_document(
    session: Session,
    level: Level,
) -> UUIDSplit:
    # Find collection ids to work with.

    q_n_total = select(func.count()).select_from(select(Document.uuid).subquery())
    n_total = session.execute(q_n_total).scalar()

    quser = (
        select(Document.uuid)
        .select_from(Document)
        .join(Grant, onclause=Grant.id_document == Document.id)
        .join(User, onclause=User.id == Grant.id_user)
        .where(
            User.uuid == "000-000-000",
            Grant.level >= level.value,
        )
    )
    uuid_granted = set(session.execute(quser).scalars())

    qother = select(Document.uuid).where(Document.uuid.not_in(uuid_granted))
    uuid_other = set(session.execute(qother).scalars())

    if n_total != (n := len(uuid_granted)) + (m := len(uuid_other)):
        raise AssertionError(
            f"Expected a total of `{n_total}` results (got `{n + m}` "
            f"entries, of which `{n}` belong to the user `000-000-000` "
            f"and the  remaining `{m}` do not)."
        )
    elif len(bad := uuid_other & uuid_granted):
        msg = "`uuid_other` and `uuid_granted` should not intersect."
        msg += f"\n{uuid_other=},\n{uuid_granted=},\n{bad=}."
        raise AssertionError(msg)
    return uuid_granted, uuid_other


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


# def split_uuid_grant(session: Session, level: Level) -> GrantSplit:
#     return GrantSplit(
#         users=split_uuid_user(session), documents=split_uuids_document(session, level)
#     )


# =========================================================================== #
# Tests


class TestAccessUser(BaseTestAccess):
    fn_access_types = dict(user=Data[ResolvedUser])

    def test_overloads(self, session: Session):
        # When a single user uuid is supplied, a single user is returned.
        session.execute(update(User).values(public=True, deleted=False))
        access = self.create_access(session, HTTPMethod.GET)

        res = access.user({"000-000-000", "99d-99d-99d"})
        assert isinstance(res, tuple)
        assert len(res) == 2
        assert all(isinstance(user, User) for user in res)

        res = access.user("000-000-000")
        assert isinstance(res, User)
        assert res.uuid == "000-000-000"

        res = access.user({"000-000-000", "99d-99d-99d"}, return_data=True)
        assert isinstance(res, Data)

    def test_deleted(self, session: Session):
        # Reject user reading self if user is deleted.
        user = User.if_exists(session, "000-000-000")
        user.deleted = True
        session.add(user)
        session.commit()

        access = self.create_access(session)
        with pytest.raises(HTTPException) as err:
            access.user("000-000-000")

        exc: HTTPException = err.value
        detail = dict(
            uuid_obj="000-000-000",
            kind_obj="user",
            msg="Object is deleted.",
        )
        assert exc.status_code == 410
        assert exc.detail == detail

        # Reject active user reading deleted user.
        user = User.if_exists(session, "99d-99d-99d")
        user.deleted = False
        _ = session.add(user) and session.commit()

        with pytest.raises(HTTPException) as err:
            access.user("000-000-000")

        exc = err.value
        assert exc.status_code == 410
        assert exc.detail == detail

    def test_modify(self, session: Session):
        # User should not be able to access another user for any method besides
        # httpx.GET
        session.execute(update(User).values(deleted=False, public=True))
        session.commit()

        access: Access
        for meth in httpcommon:
            if meth == HTTPMethod.GET:
                continue

            access = self.create_access(session, meth)
            assert access.token.uuid == "000-000-000"
            with pytest.raises(HTTPException) as err:
                access.user("99d-99d-99d")

            exc = err.value
            detail = dict(
                uuid_user_token="000-000-000",
                uuid_user="99d-99d-99d",
                msg="Cannot modify other user.",
            )
            assert exc.status_code == 403
            assert exc.detail == detail

            # Success when accessing own user with patch.
            user = access.user("000-000-000")
            assert user.uuid == "000-000-000"
            assert access.token_user.uuid == "000-000-000"

        # Changing the level to `HTTPMethod.GET` will make it such that calling
        # for another public user does not fail.
        access = self.create_access(session, HTTPMethod.GET)
        user = access.user("99d-99d-99d")
        assert user.uuid == "99d-99d-99d"
        assert access.token_user.uuid == "000-000-000"

    def test_private(self, session: Session):
        session.execute(update(User).values(deleted=False, public=False))
        session.commit()

        for method in httpcommon:
            print(method)

            # User can access self when private.
            access = self.create_access(session, method)
            user = access.user("000-000-000")
            assert user.uuid == access.token.uuid == "000-000-000"

            # User cannot access other user that is private
            assert access.token_user.uuid == "000-000-000"
            with pytest.raises(HTTPException) as err:
                access.user("99d-99d-99d")

            msg: str
            if method == HTTPMethod.GET:
                msg = "Cannot access private user."
            else:
                msg = "Cannot modify other user."

            if err := check_exc(
                err.value,
                403,
                uuid_user_token="000-000-000",
                uuid_user="99d-99d-99d",
                msg=msg,
            ):
                raise err

    def test_dne(self, session: Session):
        for method in httpcommon:
            access = self.create_access(session, method)
            with pytest.raises(HTTPException) as err:
                access.user(uuid_bad := secrets.token_urlsafe(9))

            exc = err.value
            assert exc.status_code == 404
            assert exc.detail == dict(
                uuid_obj=uuid_bad,
                kind_obj="user",
                msg="Object does not exist.",
            )


class TestAccessCollection(BaseTestAccess):
    fn_access_types = dict(collection=Data[ResolvedCollection])

    def split_uuid(
        self,
        session: Session,
    ) -> UUIDSplit:
        return split_uuid_collection(session)

    def test_overloads(self, session: Session):
        access = self.create_access(session, HTTPMethod.DELETE)

        # NOTE: Set in -> Tuple out
        res = access.collection({"eee-eee-eee", "foo-ooo-ool"})
        assert isinstance(res, tuple)
        assert len(res) == 2
        assert all(isinstance(item, Collection) for item in res)

        # NOTE: uuid in, collection out
        res = access.collection("eee-eee-eee")
        assert isinstance(res, Collection)
        assert res.uuid == "eee-eee-eee"

        res = access.collection("eee-eee-eee", return_data=True)
        assert isinstance(res, Data)
        assert res.data.kind == "collection"
        assert isinstance(res.data, ResolvedCollection)

    def test_private(self, session: Session):
        session.execute(update(User).values(deleted=False, public=True))
        session.execute(update(Collection).values(deleted=False, public=False))
        session.commit()

        (uuid_owned, *_), (uuid_other, *_) = self.split_uuid(session)

        for meth in httpcommon:
            # User cannot access the private collections of others.
            access = self.create_access(session, meth)
            with pytest.raises(HTTPException) as err:
                access.collection(uuid_other)

            if err := check_exc(
                err.value,
                403,
                msg="Cannot access private collection.",
                uuid_user="000-000-000",
                uuid_collection=uuid_other,
            ):
                raise err

            # User can access their own private collection
            collection = access.collection(uuid_owned)
            assert collection.id_user == access.token_user.id
            assert collection.uuid == uuid_owned

            # NOTE: Private users cannot have public collections. How to resolve?

    def test_deleted(self, session: Session):
        session.execute(update(User).values(deleted=False, public=True))
        session.execute(update(Collection).values(deleted=True, public=False))

        (uuid_owned, *_), (uuid_other, *_) = self.split_uuid(session)

        for meth in httpcommon:
            # User cannot read own deleted collection
            access = self.create_access(session, meth)
            with pytest.raises(HTTPException) as err:
                access.collection(uuid_owned)

            if err := check_exc(
                err.value,
                410,
                msg="Object is deleted.",
                kind_obj="collection",
                uuid_obj=uuid_owned,
            ):
                raise err

            # NOTE: Lack of permission should supercede deletion.
            with pytest.raises(HTTPException) as err:
                access.collection(uuid_other)

            if err := check_exc(
                err.value,
                403,
                uuid_collection=uuid_other,
                uuid_user="000-000-000",
                msg="Cannot access private collection.",
            ):
                raise err

    def test_dne(self, session: Session):
        # NOTE: Id should not exist 100% bc default uses `token_urlsafe(8)`.
        for method in httpcommon:
            access = self.create_access(session, method)
            with pytest.raises(HTTPException) as err:
                access.collection(uuid_obj := secrets.token_urlsafe(9))

            if err := check_exc(
                err.value,
                404,
                msg="Object does not exist.",
                uuid_obj=uuid_obj,
                kind_obj="collection",
            ):
                raise err

    def test_modify(self, session: Session):
        session.execute(update(User).values(deleted=False, public=True))
        session.execute(update(Collection).values(deleted=False, public=True))
        session.commit()

        (uuid_owned, *_), (uuid_other, *_) = self.split_uuid(session)

        user_other = User.if_exists(session, "99d-99d-99d")
        for meth in httpcommon:
            if meth == HTTPMethod.GET:
                continue

            # Cannot access when not owner
            access = self.create_access(session, meth)
            with pytest.raises(HTTPException) as err:
                access.collection(uuid_other)

            if err := check_exc(
                err.value,
                403,
                msg="Cannot modify collection.",
                uuid_user="000-000-000",
                uuid_collection=uuid_other,
            ):
                raise err

            # Can when owner, impersonate owner.
            collection = access.collection(
                uuid_other,
                resolve_user_token=user_other,
            )
            assert collection.uuid == uuid_other
            assert collection.id_user == user_other.id


class TestAccessDocument(BaseTestAccess):
    fn_access_types = dict(document=Data[ResolvedDocument])
    fn_access_ignored_params: ClassVar[Set[str]] = {"grants", "grants_index"}

    def split_uuids(self, session: Session, level: Level):
        return split_uuids_document(session, level)

    def test_overloads(self, session: Session):
        access = self.create_access(session, HTTPMethod.DELETE)
        res = access.document({"aaa-aaa-aaa", "draculaflow"})
        assert isinstance(res, tuple)
        assert len(res) == 2
        assert all(isinstance(item, Document) for item in res)

        res = access.document("aaa-aaa-aaa")
        assert isinstance(res, Document)
        assert res.uuid == "aaa-aaa-aaa"

        res = access.document({"aaa-aaa-aaa", "draculaflow"}, return_data=True)
        assert isinstance(res, Data)
        assert isinstance(res.data, ResolvedDocument)
        assert isinstance(res_collection := res.data.documents, tuple)
        assert all(isinstance(item, Document) for item in res_collection)

    def test_private(self, session: Session):
        session.execute(update(User).values(deleted=False, public=True))
        session.execute(update(Document).values(deleted=False, public=False))

        for method in httpcommon:
            # NOTE: Requires that grants exist. This does not overlap with
            #       `test_modify`.
            access = self.create_access(session, method)
            level = LevelHTTP[method.name].value
            level_next = None
            if level != Level.own:
                level_next = Level(level.value + 1)

            uuid_granted, uuid_other = self.split_uuids(session, level)
            if level_next:
                # NOTE: Cannot access documents of others.
                with pytest.raises(HTTPException) as err:
                    access.document(uuid_other, level=level_next)

                if err := check_exc(
                    err.value, 403, uuid_user="000-000-000", check_length=False
                ):
                    raise err

            # NOTE: Can access documents when level is enough.
            documents = access.document(uuid_granted, level=level)
            assert len(documents) == len(uuid_granted)
            bad = [ii.uuid for ii in documents if ii.uuid not in uuid_granted]
            if bad:
                msg = f"Unexpected documents (uuids `{bad}`) returned."
                raise AssertionError(msg)

    def test_check_user_can_access(self, session: Session):
        # ------------------------------------------------------------------- #
        # Setup

        session.execute(update(User).values(deleted=False, public=True))
        session.execute(update(Document).values(deleted=False, public=False))

        user = User.if_exists(session, "000-000-000")
        document = Document.if_exists(session, "aaa-aaa-aaa")

        grant = session.execute(
            select(Grant).where(
                Grant.id_user == user.id,
                Grant.id_document == document.id,
                Grant.pending == false(),
            )
        ).scalar()

        match grant:
            case None:
                grant = Grant(
                    id_user=user.id,
                    id_document=document.id,
                    level=Level.view,
                    pending=False,
                    pending_from=PendingFrom.granter,
                )
            case Grant():
                pass
            case _ as bad:
                T = type(bad)
                raise AssertionError(f"Unexpected type `{T}` for grant.")

        grant.deleted = False
        grant.pending = True
        grant.pending_from = PendingFrom.granter
        init_level = grant.level
        session.add(grant)
        session.commit()
        session.refresh(grant)
        assert grant.pending

        # ------------------------------------------------------------------- #
        # NOTE: Pending grant should not allow access on private doc

        detail_common = dict(
            uuid_user="000-000-000",
            uuid_document="aaa-aaa-aaa",
        )
        with pytest.raises(HTTPException) as err:
            user.check_can_access_document(document, Level.view)

        if err := check_exc(
            err.value,
            403,
            msg="Grant is pending. User must accept invitation.",
            **detail_common,  # type: ignore
        ):
            raise err

        # ------------------------------------------------------------------- #
        # NOTE: Changing the enum value should change the message returned.

        grant.pending_from = PendingFrom.grantee
        session.add(grant)
        session.commit()

        with pytest.raises(HTTPException) as err:
            user.check_can_access_document(document, Level.view)

        if err := check_exc(
            err.value,
            403,
            msg="Grant is pending. Document owner must approve request for access.",
            **detail_common,  # type: ignore
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
            # Update grant level.
            grant.level = Level(level)
            session.add(grant)
            session.commit()

            # Level should be enough
            user.check_can_access_document(document, level)

            # Cover the case where level is `view` and want to check `own`.
            levels_above = [level_next]
            if level_next == Level.own:
                levels_above.append(Level.own)

            for level_above in levels_above:
                with pytest.raises(HTTPException) as err:
                    user.check_can_access_document(document, level_above)

                if err := check_exc(
                    err.value,
                    403,
                    **detail_common,
                    msg="Grant insufficient.",
                    level_grant=level.name,
                    level_grant_required=level_above.name,
                    uuid_grant=grant.uuid,
                ):
                    raise err

        # ------------------------------------------------------------------- #
        # NOTE: Deleting the grant should result in an error raised. Grant
        #       exists but is deleted state.

        grant.deleted = True
        session.add(grant)
        session.commit()

        with pytest.raises(HTTPException) as err:
            user.check_can_access_document(document, Level.view)

        if err := check_exc(
            err.value,
            410,
            uuid_grant=grant.uuid,
            uuid_user="000-000-000",
            uuid_document="aaa-aaa-aaa",
            msg="Grant is deleted.",
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

        err, httperr = expect_exc(
            lambda: user.check_can_access_document(document, Level.view),
            403,
            uuid_user="000-000-000",
            uuid_document="aaa-aaa-aaa",
            msg="Grant does not exist.",
        )

        make_transient(grant)
        grant.level = init_level
        grant.deleted = False
        session.add(grant)
        session.commit()

    def not_exists_or_insufficient(
        self,
        session: Session,
        access: Access,
        httperr: HTTPException,
        *,
        uuid_exists_not: Set[str],
        uuid_other: Set[str],
    ):
        detail = httperr.detail
        assert isinstance(detail, dict)

        if (uuid_document := (detail).get("uuid_document")) in uuid_exists_not:
            assert detail.get("msg") == "Grant does not exist."
        else:
            assert (uuid_grant := detail.get("uuid_grant")) is not None
            grant = Grant.if_exists(session, uuid_grant)

            assert detail.get("msg") == "Grant insufficient."
            assert detail.get("level_grant_required") == access.level.name
            assert detail.get("level_grant") == grant.level.name
            assert grant.uuid_document == uuid_document

        assert uuid_document in uuid_other

    def test_modify(self, session: Session):
        """Verify that:

        1. A user cannot use any mehtods besides `GET` on a document that they
           do not own (having only public documents simplifies this situation).
        2. A user can use any method on one of their own documents WHEN THEY
           OWN it.
        """
        session.execute(update(User).values(deleted=False, public=True))
        session.execute(update(Document).values(deleted=False, public=True))
        session.commit()

        uuid_exists, uuid_exists_not = self.split_uuids(session, Level.view)
        uuid_owned, uuid_other = self.split_uuids(session, Level.own)
        for method in httpcommon:
            if method == HTTPMethod.GET:
                continue

            # NOTE: Try to access unowned documents for method should 403. The
            #       grant is insufficient or does not exist.
            access = self.create_access(session, method)
            err, httperr = expect_exc(
                lambda: access.document(uuid_other),
                403,
                check_length=False,
                uuid_user="000-000-000",
            )
            if err:
                raise err

            self.not_exists_or_insufficient(
                session,
                access,
                httperr,
                uuid_exists_not=uuid_exists_not,
                uuid_other=uuid_other,
            )

    def test_deleted(self, session: Session):
        # NOTE: Documents being private simplifies loop (bc public doc will
        #       just tell you it is deleted.
        session.execute(update(User).values(public=True, deleted=False))
        session.execute(update(Grant).values(deleted=True))
        session.execute(update(Document).values(public=False, deleted=True))
        session.commit()

        uuid_exists, uuid_exists_not = self.split_uuids(session, Level.view)
        for method in httpcommon:
            # NOTE: Should not be able to access own deleted documents.
            access = self.create_access(session, method)
            uuid_granted, uuid_other = self.split_uuids(session, access.level)
            err, httperr = expect_exc(
                lambda: access.document(uuid_granted),
                410,
                check_length=False,
                msg="Grant is deleted.",
                uuid_user="000-000-000",
            )
            if err:
                raise err

            assert isinstance(detail := httperr.detail, dict)
            assert (uuid_document := detail.get("uuid_document")) is not None
            assert uuid_document in uuid_granted

            assert (uuid_grant := detail.get("uuid_grant")) is not None
            grant = Grant.if_exists(session, uuid_grant)

            assert detail.get("uuid_document") == grant.uuid_document

            # NOTE: Lack of permission should supercede deletedness.
            err, httperr = expect_exc(
                lambda: access.document(
                    uuid_exists_not,
                    resolve_user_token="000-000-000",
                ),
                403,
                check_length=False,
                msg="Grant does not exist.",
                uuid_user="000-000-000",
            )
            if err is not None:
                raise err

            assert isinstance(httperr.detail, dict)
            assert "uuid_document" in httperr.detail
            assert httperr.detail.get("uuid_document") in uuid_other

            # NOTE: Undelete grants for user, error should be about document
            #       deletedness. This gaurentees that if a document is deleted
            #       but the grants persist, the user will not be given access
            #       to deleted.
            session.execute(update(Grant).values(deleted=False))
            session.commit()

            err, httperr = expect_exc(
                lambda: access.document(uuid_granted),
                410,
                check_length=False,
                msg="Object is deleted.",
                kind_obj="document",
            )
            if err:
                raise err

            assert isinstance(detail := httperr.detail, dict)
            assert detail.get("uuid_obj") in uuid_granted
            session.execute(update(Grant).values(deleted=True))
            session.commit()

    def test_dne(self, session: Session):
        uuid_bs = secrets.token_urlsafe(9)
        for method in httpcommon:
            access = self.create_access(session, method)
            err, httperr = expect_exc(
                lambda: access.document(uuid_bs),
                404,
                msg="Object does not exist.",
                kind_obj="document",
                uuid_obj=uuid_bs,
            )
            if err:
                raise err


class TestAccessAssignment(BaseTestAccess):
    fn_access_types = dict(
        assignment_collection=Data[ResolvedAssignmentCollection],
        assignment_document=Data[ResolvedAssignmentDocument],
    )

    def split(self, session: Session, level: Level) -> AssignmentSplit:
        return split_uuid_assignment(session, level)

    def test_overloads(self, session: Session):
        access = self.create_access(session, HTTPMethod.DELETE)

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
            assert len(tt) == 2
            assert all(isinstance(item, TT) for item in tt)

        session.execute(update(User).values(deleted=False, public=True))
        session.execute(update(Grant).values(deleted=False))
        session.execute(update(Document).values(deleted=False, public=True))
        session.commit()

        # For assignment document.
        res = access.assignment_document(
            "aaa-aaa-aaa",
            {"foo-ooo-ool", "eee-eee-eee"},
        )
        check_res(res, Document, tuple)

        res_data: Data = access.assignment_document(
            "aaa-aaa-aaa",
            {"foo-ooo-ool", "eee-eee-eee"},
            return_data=True,
        )
        check_res(res_data, Document, Data)

        assert isinstance(res_data.data, ResolvedAssignmentDocument)
        assert res_data.data.document == res[0]
        assert res_data.data.collections == res[1]

        # For assignment collection.
        res = access.assignment_collection(
            "foo-ooo-ool", {"aaa-aaa-aaa", "draculaflow"}
        )
        check_res(res, Collection, tuple)

        res_data = access.assignment_collection(
            "foo-ooo-ool",
            {"aaa-aaa-aaa", "draculaflow"},
            return_data=True,
        )
        check_res(res_data, Collection, Data)

        assert isinstance(res_data.data, ResolvedAssignmentCollection)
        assert res_data.data.collection == res[0]
        assert res_data.data.documents == res[1]

    def check_result(
        self,
        session: Session,
        res: Tuple[Collection | Document, Tuple],
        level: Level,
        *,
        uuid_t_expected: str,
        uuid_s_expected: Set[str],
        T_expected: Type,
    ) -> Tuple[Tuple[Assignment, ...], AssertionError | None]:
        match res:
            case [Collection() as tt, tuple() as ss]:
                T, S = Collection, Document
            case [Document() as tt, tuple() as ss]:
                T, S = Document, Collection
            case _:
                raise ValueError()

        # Check tt.
        msg: str = ""
        if T != T_expected:
            msg += f"Expected result to have `{T_expected}` as its first "
            msg += "element."

        assert isinstance(tt, T)
        assert tt.uuid == uuid_t_expected

        # Check ss.
        assert len(ss) == len(uuid_s_expected)
        uuid_s = uuids(ss)

        if len(extra := uuid_s - uuid_s_expected):
            msg += f"Results contains unexpected uuids `{extra}`.\n"
            msg += f"Expected any of `{uuid_t_expected}`.\n"
        if len(missing := uuid_s_expected - uuid_s):
            msg += f"Results missing uuids `{missing}`.\n"
            msg += f"Expected any of `{uuid_t_expected}`.\n"
        if bad := tuple(ss for item in ss if not isinstance(item, S)):
            msg += f"Incorrect item types in result tuple: `{bad}`."

        # Check the assignments.
        q = tt.q_select_assignment(uuid_s)
        assignments: Tuple[Assignment, ...] = tuple(session.execute(q).scalars())
        return assignments, AssertionError(msg) if msg else None

    def test_private(self, session: Session):
        session.execute(update(Collection).values(deleted=False, public=False))
        session.execute(update(Grant).values(deleted=False))
        session.execute(update(Document).values(deleted=False, public=False))
        session.commit()

        _, (uuid_doc_ungranted,) = split_uuids_document(session, Level.view)
        for method in httpcommon:
            _d = self.split(session, LevelHTTP[method].value)
            ((uuid_coll, uuid_coll_other), (uuid_doc, uuid_doc_other)) = _d
            (uuid_doc_1st, *_), (uuid_coll_1st, *_) = (uuid_doc, uuid_coll)
            (uuid_doc_1st_other, *_), (uuid_coll_1st_other, *_) = (
                uuid_doc_other,
                uuid_coll_other,
            )
            access = self.create_access(session, method)

            # NOTE: User can access their own private assignments.
            res = access.assignment_document(
                uuid_doc_1st, uuid_coll, level=access.level
            )
            _, err = self.check_result(
                session,
                res,
                level=LevelHTTP[method].value,
                uuid_t_expected=uuid_doc_1st,
                uuid_s_expected=uuid_coll,
                T_expected=Document,
            )
            if err:
                raise err

            res = access.assignment_collection(
                uuid_coll_1st, uuid_doc, level=access.level
            )
            _, err = self.check_result(
                session,
                res,
                level=LevelHTTP[method].value,
                uuid_t_expected=uuid_coll_1st,
                uuid_s_expected=uuid_doc,
                T_expected=Collection,
            )
            if err:
                raise err

            # NOTE: User cannot access the private assignments of others. Only
            #       the second argument should be invalid.
            with pytest.raises(HTTPException) as err:
                access.assignment_document(
                    uuid_doc_ungranted,
                    uuid_coll,
                    level=access.level,
                )
            if err := check_exc(
                httperr := err.value,  # type: ignore
                403,
                check_length=False,
                msg="Grant does not exist.",
                uuid_user="000-000-000",
            ):
                raise err

            detail = httperr.detail
            assert detail["uuid_document"] == uuid_doc_ungranted

            with pytest.raises(HTTPException) as err:
                access.assignment_collection(
                    uuid_coll_1st_other,
                    uuid_doc,
                    level=access.level,
                )

            if err := check_exc(
                err.value,
                403,
                msg="Cannot access private collection.",
                uuid_user="000-000-000",
                uuid_collection=uuid_coll_1st_other,
            ):
                raise err

    def test_modify(self, session: Session):
        session.execute(update(Collection).values(deleted=False, public=True))
        session.execute(update(Grant).values(deleted=False))
        session.execute(update(Document).values(deleted=False, public=True))
        session.commit()

        _, (uuid_doc_ungranted,) = split_uuids_document(session, Level.view)
        for method in httpcommon:
            if method == HTTPMethod.GET:
                continue

            _d = self.split(session, LevelHTTP[method].value)
            ((uuid_coll, uuid_coll_other), (uuid_doc, uuid_doc_other)) = _d
            (uuid_doc_1st, *_), (uuid_coll_1st, *_) = (uuid_doc, uuid_coll)
            (uuid_doc_1st_other, *_), (uuid_coll_1st_other, *_) = (
                uuid_doc_other,
                uuid_coll_other,
            )
            access = self.create_access(session, method)

            # NOTE: Can modify when granted and collection is owned.
            res = access.assignment_collection(uuid_coll_1st, uuid_doc)
            _, err = self.check_result(
                session,
                res,
                access.level,
                uuid_t_expected=uuid_coll_1st,
                uuid_s_expected=uuid_doc,
                T_expected=Collection,
            )
            if err:
                raise err

            # NOTE: Cannot modify ungranted.
            with pytest.raises(HTTPException) as err:
                access.assignment_document(
                    uuid_doc_ungranted,
                    uuid_coll,
                    level=access.level,
                )
            if err := check_exc(
                err.value,  # type: ignore
                403,
                check_length=False,
                msg="Grant does not exist.",
                uuid_user="000-000-000",
            ):
                raise err

            # NOTE: Cannot modify collection not owned.
            with pytest.raises(HTTPException) as exc:
                access.assignment_collection(uuid_coll_1st_other, uuid_doc)

            if err := check_exc(
                exc.value,
                403,
                check_length=False,
                msg="Cannot modify collection.",
                uuid_user=access.token_user.uuid,
            ):
                raise err

            assert exc.value.detail["uuid_collection"] in uuid_coll_other

            # NOTE: Insufficient grant case. Only possible when modify or >
            #       Try to modify a document with insufficient access.
            if access.level.name == "view":
                continue

            q = (
                select(Grant.level, Grant.uuid, Document.uuid)
                .join(Grant)
                .join(User, onclause=User.id == Grant.id_user)
                .where(
                    Grant.level < access.level.value,
                    Document.uuid.in_(uuid_doc_other),
                    User.uuid == access.token_user.uuid,
                )
            )
            res = session.execute(q).first()
            if res is None:
                Document.__bases__
                d = Document(
                    title="TestAccessAssignment.test_private",
                    format="md",
                    content="# TestAccessAssignment.test_private Placeholder",
                )
                _ = session.add(d) or session.commit() or session.refresh(d)
                uuid_document_insufficient = d.uuid
                level_insufficient = Level(access.level.value - 1)
                g = Grant(
                    id_document=d.id,
                    id_user=access.token_user.id,
                    level=level_insufficient,
                )
                _ = session.add(g) or session.commit() or session.refresh(g)
                uuid_grant_insufficient = g.uuid
            else:
                (
                    level_insufficient,
                    uuid_grant_insufficient,
                    uuid_document_insufficient,
                ) = res

            with pytest.raises(HTTPException) as err:
                access.assignment_document(
                    uuid_document_insufficient, uuid_coll, level=access.level
                )

            detail_expected: Dict[str, Any] = dict(
                msg="Grant insufficient.",
                uuid_user="000-000-000",
                uuid_document=uuid_document_insufficient,
                uuid_grant=uuid_grant_insufficient,
                level_grant_required=access.level.name,
                level_grant=level_insufficient.name,
            )
            if err := check_exc(err.value, 403, **detail_expected):
                raise err

            with pytest.raises(HTTPException) as err:
                access.assignment_collection(
                    uuid_coll_1st,
                    {uuid_document_insufficient},
                    level=access.level,
                )

            if err := check_exc(err.value, 403, **detail_expected):
                raise err

    def test_deleted(self, session: Session):
        session.execute(update(Collection).values(deleted=True, public=True))
        session.execute(update(Grant).values(deleted=False))
        session.execute(update(Document).values(deleted=True, public=True))
        session.commit()

        _, (uuid_doc_ungranted,) = split_uuids_document(session, Level.view)
        for method in httpcommon:
            if method == HTTPMethod.GET:
                continue

            _d = self.split(session, LevelHTTP[method].value)
            ((uuid_coll, uuid_coll_other), (uuid_doc, uuid_doc_other)) = _d
            (uuid_doc_1st, *_), (uuid_coll_1st, *_) = (uuid_doc, uuid_coll)
            (uuid_doc_1st_other, *_), (uuid_coll_1st_other, *_) = (
                uuid_doc_other,
                uuid_coll_other,
            )
            access = self.create_access(session, method)

            # NOTE: Should say that the document is deleted when accessing own.
            err, httperr = expect_exc(
                lambda: access.assignment_document(uuid_doc_1st, uuid_coll),
                410,
                msg="Object is deleted.",
                uuid_obj=uuid_doc_1st,
                kind_obj="document",
            )
            if err:
                raise err

            # NOTE: Lack of permission supercedes deletedness.
            err, httperr = expect_exc(
                lambda: access.assignment_document(uuid_doc_ungranted, uuid_coll),
                403,
                msg="Grant does not exist.",
                uuid_document=uuid_doc_ungranted,
                uuid_user=access.token_user.uuid,
                level=access.level.name,
            )
            if err:
                raise err

            # NOTE: Public collection should tell anyone it is deleted.
            err, httperr = expect_exc(
                lambda: access.assignment_collection(uuid_coll_1st_other, uuid_doc),
                410,
                msg="Object is deleted.",
                uuid_obj=uuid_coll_1st_other,
                kind_obj="collection",
            )
            if err:
                raise err

    def test_dne(self, session: Session):
        uuid_bs = secrets.token_urlsafe(9)
        uuid_bs_set = {secrets.token_urlsafe(7) for _ in range(10)}

        for method in httpcommon:
            access = self.create_access(session, method)

            err, httperr = expect_exc(
                lambda: access.assignment_collection(uuid_bs, uuid_bs_set),
                404,
                msg="Object does not exist.",
                uuid_obj=uuid_bs,
                kind_obj="collection",
            )
            if err:
                raise err

            err, httperr = expect_exc(
                lambda: access.assignment_document(uuid_bs, uuid_bs_set),
                404,
                msg="Object does not exist.",
                uuid_obj=uuid_bs,
                kind_obj="document",
            )
            if err:
                raise err


class TestAccessGrant(BaseTestAccess):
    fn_access_types = dict(
        grant_user=Data[ResolvedGrantUser],
        grant_document=Data[ResolvedGrantDocument],
    )
    kinds = {KindObject.user, KindObject.document, KindObject.grant}

    def test_self_access_only(self, dummy: DummyProvider):
        """For ``/grants/users/{uuid_user}`` only."""

        document = Document.if_exists(dummy.session, "aaa-aaa-aaa")
        document.deleted = False
        session = dummy.session
        session.add(document)
        session.commit()
        session.refresh(document)
        dummy.visability(self.kinds, deleted=False, public=True).refresh()

        # NOTE: Invariance with method
        for method in httpcommon:
            access = Access(session, dummy.token, method)
            err, _ = expect_exc(
                lambda: access.grant_user("000-000-000", {"aaa-aaa-aaa"}),
                403,
                msg="User can only access own grants.",
                uuid_user="000-000-000",
                uuid_user_token=dummy.token.uuid,
            )
            if err is not None:
                raise err

            access.grant_user(dummy.user.uuid, {"aaa-aaa-aaa"})

    def test_owner_access_only(self, auth: Auth, session: Session):
        """For ``/grants/documents/{uuid_document}`` only."""

        def doit(access: Access, doc: Document):
            return access.grant_document(doc.uuid, {"000-000-000"})

        dummy = DummyProvider(
            auth, session, user=User.if_exists(session, "000-000-000")
        )
        document_own = dummy.get_document(Level.own)
        document_modify = dummy.get_document(Level.modify)
        document_view = dummy.get_document(Level.view)
        document_other = Document.if_exists(session, "-0---0---0-")
        print("document_other")
        common_insufficient: Dict[str, Any] = dict(
            msg="Grant insufficient.",
            uuid_user="000-000-000",
            level_grant_required="own",
            check_length=False,
        )

        # NOTE: Invariance with method
        for method in httpcommon:
            # Cannot access other
            access = self.create_access(session, method)
            err, _ = expect_exc(
                lambda: doit(access, document_other),
                403,
                msg="Grant does not exist.",
                uuid_user="000-000-000",
                uuid_document=document_other.uuid,
                level="own",
            )
            if err:
                raise err

            # Cannot access with only view.
            access = self.create_access(session, method)
            err, _ = expect_exc(
                lambda: doit(access, document_view),
                403,
                level_grant="view",
                uuid_document=document_view.uuid,
                **common_insufficient,
            )
            if err:
                raise err

            # Cannot access with only modify
            access = self.create_access(session, method)
            err, _ = expect_exc(
                lambda: doit(access, document_modify),
                403,
                level_grant="modify",
                uuid_document=document_modify.uuid,
                **common_insufficient,
            )
            if err:
                raise err

            # Can access with own
            doit(access, document_own)

    def test_overloads(self, session: Session):
        access = self.create_access(session)

        res = access.grant_user("000-000-000", {"aaa-aaa-aaa"})
        assert len(res) == 2
        assert isinstance(res, tuple)

        uu, dd = res
        assert isinstance(uu, User)
        assert isinstance(dd, tuple)

        res = access.grant_user("000-000-000", {"aaa-aaa-aaa"}, return_data=True)
        assert isinstance(res, Data)
        assert isinstance(res.data, ResolvedGrantUser)

        # -------------------------------------------------------------------- #

        res = access.grant_document("aaa-aaa-aaa", {"000-000-000"})
        assert len(res) == 2
        assert isinstance(res, tuple)

        dd, uu = res
        assert isinstance(dd, Document)
        assert isinstance(uu, Tuple)

        res = access.grant_document("aaa-aaa-aaa", {"000-000-000"}, return_data=True)
        assert isinstance(res, Data)
        assert isinstance(res.data, ResolvedGrantDocument)

    def check_result(
        self,
        session: Session,
        res: Tuple[User | Document, Tuple],
        level: Level,
        *,
        uuid_t_expected: str,
        uuid_s_expected: Set[str],
        T_expected: Type,
    ) -> Tuple[Tuple[Grant, ...], AssertionError | None]:
        match res:
            case [User() as tt, tuple() as ss]:
                T, S = User, Document
            case [Document() as tt, tuple() as ss]:
                T, S = Document, User
            case _:
                raise ValueError()

        # Check tt.
        msg: str = ""
        if T != T_expected:
            msg += f"Expected result to have `{T_expected}` as its first "
            msg += "element."

        assert isinstance(tt, T)
        assert tt.uuid == uuid_t_expected

        # Check ss.
        assert len(ss) == len(uuid_s_expected)
        uuid_s = uuids(ss)

        if len(extra := uuid_s - uuid_s_expected):
            msg += f"Results contains unexpected uuids `{extra}`.\n"
            msg += f"Expected any of `{uuid_t_expected}`.\n"
        if len(missing := uuid_s_expected - uuid_s):
            msg += f"Results missing uuids `{missing}`.\n"
            msg += f"Expected any of `{uuid_t_expected}`.\n"
        if bad := tuple(ss for item in ss if not isinstance(item, S)):
            msg += f"Incorrect item types in result tuple: `{bad}`."

        # Check grants
        q = tt.q_select_grants(uuid_s)
        grants: Tuple[Grant, ...] = tuple(session.execute(q).scalars())

        if bad := tuple(item for item in grants if item.level.value < level.value):
            msg += f"Expected assignments to have level `{level}`. "
            msg += "The following assignments do not have the correct level:\n"
            msg += stringify(grants) + "\n"

        return grants, AssertionError(msg) if msg else None

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
    def test_modify(self, session: Session):
        """See the note on `test_private`` about access.

        Tl;dr: Access is determined by the source. Thus this test is the same
               as the access rules for the source of the grants.
        """

    def test_deleted(self, dummy: DummyProvider):
        dummy.visability(
            {KindObject.user, KindObject.document}, deleted=True, public=True
        ).refresh()
        document_other = dummy.get_document(None)
        document_not_deleted = dummy.documents[0]
        document_not_deleted.deleted = False

        session = dummy.session
        session.add(document_not_deleted)
        session.commit()
        session.refresh(document_not_deleted)

        token = dummy.token

        for method in httpcommon:
            print(method)

            # NOTE: Trying to access grants for deleted should fail with 410.
            access = Access(session, token, method)
            err, httperr = expect_exc(
                lambda: access.grant_user(dummy.user, dummy.documents),
                410,
                msg="Object is deleted.",
                uuid_obj=dummy.user.uuid,
                kind_obj="user",
            )
            if err:
                raise err

            err, httperr = expect_exc(
                lambda: access.grant_user(dummy.user, dummy.documents),
                410,
                msg="Object is deleted.",
                uuid_obj=dummy.user.uuid,
                kind_obj="user",
            )
            if err:
                raise err

            # NOTE: Adding `exclude_deleted` should result in no errors raised.
            access.grant_user(dummy.user, dummy.documents, exclude_deleted=False)

            # NOTE: Trying to access deleted documents with active user should
            #       raise a similar error.
            dummy.visability({KindObject.user}, deleted=False, public=True)
            dummy.refresh()
            err, httperr = expect_exc(
                lambda: access.grant_user(dummy.user, dummy.documents),
                410,
                msg="Object is deleted.",
                kind_obj="document",
                check_length=False,
            )
            if err:
                raise err

            dummy.visability({KindObject.user}, deleted=True, public=True)
            dummy.refresh()

            # NOTE: Adding `exclude_deleted` should result in no erros raised.
            access.grant_user(dummy.user, dummy.documents, exclude_deleted=False)

    def test_pending(self, dummy: DummyProvider):
        session = dummy.session
        dummy.visability(
            {KindObject.grant, KindObject.user, KindObject.document},
            deleted=False,
            public=False,
        )
        uuid_document = Document.resolve_uuid(session, dummy.documents)

        document = dummy.get_document(Level.own)
        grant = dummy.get_grant(document)

        grant.level = Level.own
        session.add(grant)
        session.commit()

        msgs = {
            PendingFrom.grantee: "Grant is pending. Document owner must approve request for access.",
            PendingFrom.granter: "Grant is pending. User must accept invitation.",
        }
        for method in httpcommon:
            for pending_from in (PendingFrom.grantee, PendingFrom.granter):
                # NOTE: Should reject pending grants. It is important to note
                #       that the grants for a user on their own original
                #       documents will never be pending hence the mutations
                #       here.
                access = Access(dummy.session, dummy.token, method)
                for grant in dummy.grants:
                    grant.pending = True
                    grant.pending_from = pending_from
                    session.add(grant)
                session.commit()

                err, httperr = expect_exc(
                    lambda: access.grant_user(dummy.user, dummy.documents),
                    403,
                    msg=msgs[pending_from],
                    uuid_user=dummy.user.uuid,
                    check_length=False,
                )
                if err:
                    raise err

                assert httperr.detail["uuid_document"] in uuid_document

                err, httperr = expect_exc(
                    lambda: access.grant_document(document, {dummy.user.uuid}),
                    403,
                    msg=msgs[pending_from],
                    uuid_user=dummy.user.uuid,
                    uuid_document=document.uuid,
                    check_length=False,
                )
                if err:
                    raise err

                # NOTE: If ``exclude_pending`` is ``False`` the no error.
                access.grant_user(dummy.user, dummy.documents, pending=True)
                access.grant_document(document, {dummy.user.uuid}, pending=True)

    def test_dne(self, dummy: DummyProvider):
        dummy.visability(
            {KindObject.user, KindObject.document, KindObject.grant},
            deleted=False,
            public=True,
        )
        document = dummy.get_document(Level.own)
        grant = dummy.get_grant(document)
        assert grant.level == Level.own

        for method in httpcommon:
            access = Access(dummy.session, dummy.token, method)
            uuid_obj = secrets.token_urlsafe(8)

            # NOTE: Filters out documents that do not exist.
            f_user, f_document = access.grant_user(dummy.user, {uuid_obj})
            assert f_user == dummy.user
            assert len(f_document) == 0

            f_document, f_user = access.grant_document(document, {uuid_obj})
            assert f_document == document
            assert len(f_user) == 0

            # NOTE: Raises when source does not exist.
            err, httperr = expect_exc(
                lambda: access.grant_document(uuid_obj, {document.uuid}),
                404,
                msg="Object does not exist.",
                uuid_obj=uuid_obj,
                kind_obj="document",
            )
            if err:
                raise err

            err, httperr = expect_exc(
                lambda: access.grant_user(uuid_obj, {document.uuid}),
                404,
                msg="Object does not exist.",
                uuid_obj=uuid_obj,
                kind_obj="user",
            )
            if err:
                raise err


class TestAccessEvent(BaseTestAccess):
    fn_access_types = dict(event=Data[ResolvedEvent])
    kinds = {KindObject.event}

    @pytest.mark.skip
    def test_private(self, session: Session):
        """The `private` column does not apply to events."""

    def test_modify(self, dummy: DummyProvider):
        """Access is invarient with respect to method. Modifying an event
        requires that the user own the event directly, which is the same
        requirement for read.
        """
        event_other = dummy.other(KindObject.event)

        # NOTE: There is no public column!
        dummy.visability({KindObject.event}, deleted=False, public=True).refresh()
        for method in httpcommon:
            access = Access(dummy.session, dummy.token, method)
            data = access.event(dummy.events, return_data=True)
            assert isinstance(data, Data)
            assert isinstance(data.data, ResolvedEvent)
            assert len(data.data.events) == len(dummy.events)

            err, _ = expect_exc(
                lambda: access.event(event_other),
                403,
                msg="User cannot access event.",
                uuid_event=event_other.uuid,
                uuid_user=dummy.user.uuid,
            )
            if err is not None:
                raise err

    def test_deleted(self, dummy: DummyProvider):
        event = dummy.events[0]
        dummy.visability(self.kinds, deleted=True, public=True).refresh()

        for method in httpcommon:
            access = Access(dummy.session, dummy.token, method)

            err, _ = expect_exc(
                lambda: access.event(event),
                410,
                msg="Object is deleted.",
                uuid_obj=event.uuid,
                kind_obj="event",
            )
            if err is not None:
                raise err

            # `exclude_deleted=False` should result in no error.
            access.event(event, exclude_deleted=False)

    def test_dne(self, dummy: DummyProvider):
        for method in httpcommon:
            access = Access(dummy.session, dummy.token, method)
            uuid_obj = secrets.token_urlsafe(8)
            err, _ = expect_exc(
                lambda: access.event(uuid_obj),
                404,
                msg="Object does not exist.",
                uuid_obj=uuid_obj,
                kind_obj="event",
            )

    def test_overloads(self, dummy: DummyProvider):
        dummy.visability(self.kinds, deleted=False, public=True).refresh()
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


@pytest.mark.skip
def test_with_access(session: Session, auth: Auth):
    """Test the intended functionality of `with_access`."""

    class Barf(WithAccess):
        @with_access(Access.d_user)
        def user(self, data: Data) -> Data:
            # Tack on an event when chained.
            print(data)
            data.event = Event(
                **self.event_common,
                kind=KindEvent.update,
                kind_obj=KindObject.user,
                uuid_obj=data.data.user.uuid,
            )
            session.add(data.event)
            session.commit()
            session.refresh(data.event)

            return data

    b = Barf(
        session,
        {"uuid": "000-000-000"},
        HTTPMethod.PATCH,
        api_origin="tests",
    )

    assert b.access is not None
    assert isinstance(b.access, Access)
    assert callable(b.user)

    data = b.user("000-000-000", resolve_user_token=b.token_user)
    assert data.event is not None
    assert data.event.uuid is not None

    sig_access = inspect.signature(Access.d_user)
    sig_barf = inspect.signature(Barf.user)

    assert "return_data" not in sig_access.parameters
    assert "return_data" not in sig_barf.parameters
    assert len(sig_access.parameters) == len(sig_barf.parameters)
    assert sig_barf.return_annotation == Data
    assert b.access is not None
    assert isinstance(b.access, Access)
    assert callable(b.user)

    data = b.user("000-000-000", resolve_user_token=b.token_user)
    assert data.event is not None
    assert data.event.uuid is not None

    sig_access = inspect.signature(Access.d_user)
    sig_barf = inspect.signature(Barf.user)

    assert "return_data" not in sig_access.parameters
    assert "return_data" not in sig_barf.parameters
    assert len(sig_access.parameters) == len(sig_barf.parameters)
    assert sig_barf.return_annotation == Data
