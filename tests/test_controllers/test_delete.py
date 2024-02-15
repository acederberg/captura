from http import HTTPMethod
from typing import Set, Tuple, Type, TypedDict

import pytest
from app import util
from app.auth import Auth, Token
from app.models import Assignment, Collection, Document, Grant, KindObject, User
from app.views.create import Upsert
from app.views.delete import AssocData, Delete
from sqlalchemy import update
from sqlalchemy.orm import Session


@pytest.fixture
def delete(session: Session) -> Delete:
    return Delete(
        session,
        dict(uuid="000-000-000"),
        HTTPMethod.POST,
        detail="From `test_delete.py`.",
        api_origin="./tests/test_controllers/test_delete.py",
    )


# class TFParams(TypedDict):
#     source: Type
#     target: Type
#     uuid_source: Set[str]
#     uuid_target: Set[str]
#
#
# tfparams = list(
#     TFParams(
#         source=User,
#         target=Document,
#         uuid_source={"000-000-000"},
#         uuid_target={"aaa-aaa-aaa", ""},
#     ),
#     TFParams(
#
#     ),
#
#
# )
#


# @pytest.mark.parametrize("tfparam", tfparams)
class TestTryForce:
    @pytest.fixture(autouse=True)
    def before_all(self, session, load_tables):
        self.restore_state(session)

    def restore_state(self, session):
        session.execute(update(User).values(deleted=False, public=True))
        session.execute(update(Document).values(deleted=False, public=True))
        session.execute(update(Collection).values(deleted=False, public=True))
        session.execute(update(Grant).values(deleted=False))
        session.execute(update(Assignment).values(deleted=False))
        session.commit()

    def test_split_assoc(self, delete: Delete) -> None:
        session = delete.session
        user = User.if_exists(session, "000-000-000")
        uuid_doc = {"aaa-aaa-aaa", "draculaflow"}
        uuid_grant = {"888-888-888", "e-eee-eee-e"}
        documents = Document.if_many(session, uuid_doc)
        grants = Grant.if_many(session, uuid_grant)
        assert len(documents) == 2
        assert len(grants) == 2

        # Check return type
        res = delete.split_assocs(Grant, user, uuid_doc)
        assert isinstance(res, AssocData)

        assert res.uuid_target_active == uuid_doc
        assert res.uuid_assoc_active == uuid_grant
        assert not len(res.uuid_target_deleted)
        assert not len(res.uuid_assoc_deleted)

        # Delete one grant.
        grant1, grant2 = grants
        grant1.deleted = True
        session.add(grant1)
        session.commit()

        res = delete.split_assocs(Grant, user, uuid_doc)
        assert len(res.uuid_target_active) == 1
        assert grant2.uuid_document in res.uuid_target_active

        assert len(res.uuid_assoc_active) == 1
        assert grant2.uuid in res.uuid_assoc_active

        assert len(res.uuid_target_deleted) == 1
        assert len(res.uuid_assoc_deleted) == 1

    @pytest.mark.parametrize(
        "delete, T_source, uuid_source, T_target, uuid_target, T_assoc, uuid_assoc",
        [
            (
                None,
                User,
                "000-000-000",
                Document,
                {"aaa-aaa-aaa", "draculaflow"},
                Grant,
                {"e-eee-eee-e", "888-888-888"},
            ),
            (
                None,
                Document,
                "aaa-aaa-aaa",
                User,
                {"000-000-000", "99d-99d-99d"},
                Grant,
                {"5-555-555-5", "e-eee-eee-e"},
            ),
            (
                None,
                Document,
                "aaa-aaa-aaa",
                Collection,
                {"eee-eee-eee", "foo-ooo-ool"},
                Assignment,
                {"aaa-aaa-eee", "aaa-foo-ool"},
            ),
            (
                None,
                Collection,
                "foo-ooo-ool",
                Document,
                {
                    "ex-parrot",
                    "aaa-aaa-aaa",
                    "petshoppe--",
                    "foobar-spam",
                    "draculaflow",
                },
                Assignment,
                {
                    "ex--foo-ool",
                    "aaa-foo-ool",
                    "petshopfool",
                    "barspamfool",
                    "draculafool",
                },
            ),
        ],
        indirect=["delete"],
    )
    def test_split_assoc_too(
        self,
        delete: Delete,
        T_source: Type,
        uuid_source: str,
        T_target: Type,
        uuid_target: Set[str],
        T_assoc: Type,
        uuid_assoc: Set[str],
    ) -> None:
        print(uuid_source, uuid_target, uuid_assoc)
        print(T_source, T_target, T_assoc)
        session = delete.session
        source = T_source.if_exists(session, uuid_source)
        targets = T_target.if_many(session, uuid_target)
        assocs = T_assoc.if_many(session, uuid_assoc)

        assert (n_target := len(targets)) == len(uuid_target)
        assert (n_assoc := len(assocs)) == len(uuid_assoc)

        # Check return type
        res = delete.split_assocs(T_assoc, source, uuid_target)
        assert isinstance(res, AssocData)

        assert res.uuid_target_active == uuid_target
        assert res.uuid_assoc_active == uuid_assoc
        assert not (len(res.uuid_target_deleted))
        assert not (len(res.uuid_assoc_deleted))

        # Delete one grant.
        assoc1, assoc2, *_ = assocs
        assoc1.deleted = True
        session.add(assoc1)
        session.commit()

        kind_obj = KindObject(T_target.__tablename__)
        uuid_target_attr = f"uuid_{kind_obj.name}"

        res = delete.split_assocs(T_assoc, source, uuid_target)
        assert len(res.uuid_target_active) == n_target - 1
        assert getattr(assoc2, uuid_target_attr) in res.uuid_target_active

        assert len(res.uuid_assoc_active) == n_assoc - 1
        assert assoc2.uuid in res.uuid_assoc_active

        assert len(res.uuid_target_deleted) == 1
        assert len(res.uuid_assoc_deleted) == 1

    def test__try_force_grant_user(self, delete: Delete) -> None:
        # Setup hell
        # sess = delete.session
        # sess.execute(update(Collection).values(deleted=False, public=True))
        # sess.execute(update(User).values(deleted=False, public=True))
        # sess.execute(update(Document).values(deleted=False, public=True))
        # sess.execute(update(Grant).values(deleted=False))
        # sess.execute(update(Assignment).values(deleted=False))

        # These should exist bc assets.
        # collections = Collection.if_many(
        #     sess, uuid_coll := {"foo-ooo-ool", "eee-eee-eee"}
        # )
        # documents = Document.if_many(sess, uuid_doc := {"aaa-aaa-aaa", "draculaflow"})
        # users = User.if_many(sess, uuid_user := {"000-000-000", "99d-99d-99d"})

        session = delete.session
        user = User.if_exists(session, "000-000-000")
        uuid_doc = {"aaa-aaa-aaa", "draculaflow"}
        documents = Document.if_many(session, uuid_doc)
        assert len(documents) == 2

        # Verify that grants exist.
        grants = Grant.resolve_from_target(session, user, uuid_doc)
        assert len(grants) == 2

        # Actual tests.
        res = delete._try_force(Grant, user, uuid_doc)
        assert len(res) == 2

        uuid_target_active, q_del = res
        assert uuid_target_active == uuid_doc

        # Execute q_del, verify result.
        util.sql(session, q_del)
        session.execute(q_del)
        session.commit()
        for grant in grants:
            session.refresh(grant)

        assert all(grant.deleted for grant in grants)

        # Deactivate 1 grant
        self.restore_state(session)
        grant_1, _ = grants
        grant_1.deleted = True
        session.commit()

        # Only one back, all that matters is if the grant is active.
        uuid_target_active, q_del = delete._try_force(Grant, user, uuid_doc)
        assert len(uuid_target_active) == 1
