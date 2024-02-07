import secrets
from http import HTTPMethod
from typing import Any, Dict, Set, Tuple

import pytest
from app import util
from app.auth import Token
from app.models import (
    Assignment,
    Collection,
    Document,
    Grant,
    Level,
    LevelHTTP,
    ResolvableSingular,
    User,
    UUIDSplit,
)
from app.views.access import Access
from fastapi import HTTPException
from sqlalchemy import func, literal_column, select, update
from sqlalchemy.orm import Session, make_transient
from tests.test_controllers.util import check_exc, expect_exc

logger = util.get_logger(__name__)
httpcommon = (
    HTTPMethod.GET,
    HTTPMethod.POST,
    HTTPMethod.PUT,
    HTTPMethod.PATCH,
    HTTPMethod.DELETE,
)
methods_required = {
    "test_cannot_modify_not_owned",
    "test_cannot_access_deleted",
    "test_cannot_access_non_existing",
    "test_cannot_access_private",
}


# Checks that the required methods are included. Generates warnings when
class AccessTestMeta(type):

    allow_missing: bool = False

    def __new__(cls, name, bases, namespace):
        T = super().__new__(cls, name, bases, namespace)
        if T.allow_missing:
            logger.warning("Not checking that `%s` has all required methods.", name)
            return T
        elif name == "BaseTestAccess":
            return T

        methods = {meth: getattr(T, meth, None) for meth in methods_required}
        if len(bad := tuple(mm for mm, value in methods.items() if value is None)):
            raise ValueError(f"`{name}` missing methods `{bad}`.")
        elif len(
            bad := tuple(name for name, value in methods.items() if not callable(value))
        ):
            raise ValueError(f"`{name}` has attributes `{bad}` that are not callable.")

        return T


class BaseTestAccess(metaclass=AccessTestMeta):
    """Inherit from this to make sure that the required methods are defined on
    each class instance.

    Use the following template:

    .. code:: python
        class Test<Table>Access(BaseTestAccess):
            def test_cannot_access_private(self, session: Session): ...
            def test_cannot_modify_not_owned(self, session: Session): ...
            def test_cannot_access_deleted(self, session: Session): ...
            def test_cannot_access_non_existing(self, session: Session): ...
    """

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


class TestUserAccess(BaseTestAccess):

    def test_cannot_access_deleted(self, session: Session):

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

    def test_cannot_modify_not_owned(self, session: Session):

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

    def test_cannot_access_private(self, session: Session):

        session.execute(update(User).values(deleted=False, public=False))
        session.commit()

        # User can access self when private.
        access = self.create_access(session, HTTPMethod.GET)
        user = access.user("000-000-000")
        assert user.uuid == access.token.uuid == "000-000-000"

        # User cannot access other user that is private
        assert access.token_user.uuid == "000-000-000"
        with pytest.raises(HTTPException) as err:
            access.user("99d-99d-99d")

        exc: HTTPException = err.value
        assert exc.status_code == 403
        assert exc.detail == dict(
            uuid_user_token="000-000-000",
            uuid_user="99d-99d-99d",
            msg="User is not public.",
        )

    def test_cannot_access_non_existing(self, session: Session):

        access = self.create_access(session, HTTPMethod.GET)
        with pytest.raises(HTTPException) as err:
            access.user(uuid_bad := secrets.token_urlsafe(9))

        exc = err.value
        assert exc.status_code == 404
        assert exc.detail == dict(
            uuid_obj=uuid_bad,
            kind_obj="user",
            msg="Object does not exist.",
        )


class TestCollection(BaseTestAccess):
    @pytest.fixture
    def split_uuid_collection(
        self,
        session: Session,
    ) -> UUIDSplit:
        # Find collection ids to work with.
        q = select(Collection.uuid)
        quser = q.join(User).where(User.uuid == "000-000-000").limit(5)
        uuid_collection_user = set(session.execute(quser).scalars())
        qother = q.where(Collection.uuid.not_in(uuid_collection_user)).limit(5)
        uuid_collection_other = set(session.execute(qother).scalars())

        assert len(uuid_collection_user), "Expected collections."
        assert len(uuid_collection_other), "Expected collections."
        return uuid_collection_user, uuid_collection_other

    def test_cannot_access_private(
        self,
        session: Session,
        split_uuid_collection: UUIDSplit,
    ):
        session.execute(update(User).values(deleted=False, public=True))
        session.execute(update(Collection).values(deleted=False, public=False))
        session.commit()

        (uuid_owned, *_), (uuid_other, *_) = split_uuid_collection

        # User cannot access the private collections of others.
        access = self.create_access(session, HTTPMethod.GET)
        with pytest.raises(HTTPException) as err:
            access.collection(uuid_other)

        exc: HTTPException = err.value
        assert exc.status_code == 403

        # User can access their own private collection
        collection = access.collection(uuid_owned)
        assert collection.id_user == access.token_user.id

        # NOTE: Private users cannot have public collections. How to resolve?

    def test_cannot_access_deleted(
        self, session: Session, split_uuid_collection: UUIDSplit
    ):
        session.execute(update(User).values(deleted=False, public=True))
        session.execute(update(Collection).values(deleted=True, public=True))

        (uuid_owned, *_), (uuid_other, *_) = split_uuid_collection

        for meth in httpcommon:
            # User cannot read own deleted collection
            access = self.create_access(session, meth)
            with pytest.raises(HTTPException) as err:
                access.collection(uuid_owned)

            exc: HTTPException = err.value
            assert exc.status_code == 410

            # User cannot read deleted collection of other
            with pytest.raises(HTTPException) as err:
                access.collection(uuid_other)

            exc = err.value
            assert exc.status_code == 410

    def test_cannot_access_non_existing(self, session: Session):
        # NOTE: Id should not exist 100% bc default uses `token_urlsafe(8)`.
        access = self.create_access(session, HTTPMethod.GET)
        with pytest.raises(HTTPException) as err:
            access.collection(secrets.token_urlsafe(9))

        exc: HTTPException = err.value
        assert exc.status_code == 404

    def test_cannot_modify_not_owned(
        self, session: Session, split_uuid_collection: UUIDSplit
    ):
        session.execute(update(User).values(deleted=False, public=True))
        session.execute(update(Collection).values(deleted=False, public=True))
        session.commit()

        (uuid_owned, *_), (uuid_other, *_) = split_uuid_collection

        user_other = User.if_exists(session, "99d-99d-99d")
        for meth in httpcommon:
            if meth == HTTPMethod.GET:
                continue

            # Cannot access when not owner
            access = self.create_access(session, meth)
            with pytest.raises(HTTPException) as err:
                access.collection(uuid_other)

            exc = err.value
            assert exc.status_code == 403

            # Can when owner, impersonate owner.
            collection = access.collection(
                uuid_other,
                resolve_user_token=user_other,
            )
            assert collection.uuid == uuid_other
            assert collection.id_user == user_other.id


class TestDocumentAccess(BaseTestAccess):
    def split_uuids(
        self,
        session: Session,
        level: Level,
        no_check=False,
    ) -> UUIDSplit:
        # Find collection ids to work with.

        q_n_total = select(func.count()).select_from(select(Document.uuid))
        n_total = session.execute(q_n_total).scalar()

        quser = (
            select(Document.uuid)
            .select_from(Document)
            .join(Grant)
            .join(User)
            .where(
                User.uuid == "000-000-000",
                Grant.level >= level.value,
            )
        )
        uuid_granted = set(session.execute(quser).scalars())

        print("quser")
        util.sql(session, quser)
        print()

        qother = select(Document.uuid).where(Document.uuid.not_in(uuid_granted))
        uuid_other = set(session.execute(qother).scalars())

        # print("qother")
        # util.sql(session, qother)
        # print()

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

    def test_cannot_access_private(self, session: Session):
        session.execute(update(User).values(deleted=False, public=True))
        session.execute(update(Document).values(deleted=False, public=False))

        for method in httpcommon:
            # NOTE: Requires that grants exist. This does not overlap with
            #       `test_cannot_modify_not_owned`.
            access = self.create_access(session, method)
            level = LevelHTTP[method.name].value
            level_next = None
            if level != Level.own:
                level_next = Level(level.value + 1)

            # print()
            # print("########################################################")
            # print("test_cannot_access_private")
            # print()
            #
            uuid_granted, uuid_other = self.split_uuids(session, level, no_check=True)
            #
            # print(f"{uuid_granted=}")
            # print(f"{uuid_other=}")
            # print(f"{level=}")
            # print(f"{level_next=}")
            # print()

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
        session.execute(update(User).values(deleted=False, public=True))
        session.execute(update(Document).values(deleted=False, public=False))

        user = User.if_exists(session, "000-000-000")
        document = Document.if_exists(session, "aaa-aaa-aaa")

        grant = session.execute(
            select(Grant).where(
                Grant.id_user == user.id,
                Grant.id_document == document.id,
            )
        ).scalar()

        match grant:
            case None:
                grant = Grant(id_user=user.id, id_document=document.id)
            case Grant():
                pass
            case _ as bad:
                T = type(bad)
                raise AssertionError(f"Unexpected type `{T}` for grant.")

        grant.deleted = False
        init_level = grant.level
        session.add(grant)
        session.commit()

        assert grant.uuid_document == document.uuid
        assert grant.uuid_user == user.uuid
        assert not grant.deleted

        detail_common = dict(
            uuid_user="000-000-000",
            uuid_document="aaa-aaa-aaa",
        )
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
                    print(grant.deleted)
                    print(grant.level)
                    print(grant.uuid)
                    raise err

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

    def test_cannot_modify_not_owned(self, session: Session):
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

            # Can access own documents with aribriary level.
            # if level == Level.own:
            #     documents = access.document(uuid_granted)
            #     assert len(documents) == len(uuid_granted)
            #     bad = tuple(
            #         document.uuid
            #         for document in documents
            #         if document.uuid not in uuid_granted
            #     )
            #     if bad:
            #         msg = f"Unxpected document with uuids "
            #         raise AssertionError(msg + f"`{uuid_granted}` returned.")
            # else:
            #     tryaccess(
            #         access,
            #         uuid_granted,
            #         resolve_user_token="000-000-000",
            #     )

    def test_cannot_access_deleted(self, session: Session):

        session.execute(update(User).values(public=True, deleted=False))
        session.execute(update(Grant).values(deleted=True))
        session.execute(update(Document).values(public=True, deleted=True))
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
                print(access.level)
                print(method)
                raise err

            assert isinstance(detail := httperr.detail, dict)
            assert detail.get("uuid_obj") in uuid_granted
            session.execute(update(Grant).values(deleted=True))
            session.commit()

            # Lack of permission should supercede deletedness.
            # err, httperr = expect_exc(
            #     lambda: access.document(uuid_other, uuid_user_token="99d-99d-99d"),
            #     403,
            #     `
            #
            #
            # )

    def test_cannot_access_non_existing(self, session: Session):

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


class TestAssignmentAccess(BaseTestAccess):
    def test_cannot_access_private(self, session: Session):
        assert False

    def test_cannot_modify_not_owned(self, session: Session):
        assert False

    def test_cannot_access_deleted(self, session: Session):
        assert False

    def test_cannot_access_non_existing(self, session: Session):
        assert False
