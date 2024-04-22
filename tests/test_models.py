# =========================================================================== #
import secrets
from typing import Any, Dict, List, Set, Tuple

import pytest
from sqlalchemy import func, literal_column, select
from sqlalchemy.orm import Session

# --------------------------------------------------------------------------- #
from app import __version__, util
from app.auth import Auth
from app.fields import Level, PendingFrom
from app.models import (
    Assignment,
    Collection,
    Document,
    Event,
    Grant,
    KindEvent,
    KindObject,
    KindSelect,
    Resolvable,
    resolve_model,
)
from tests.check import Check
from tests.dummy import DummyHandler, DummyProvider

logger = util.get_logger(__name__)


def test_flattened():
    def make_uuid(char: str) -> str:
        return "-".join(char * 3 for _ in range(3))

    def make(char: str, children: List[Event] = list()) -> Event:
        uuid = make_uuid(char)
        return Event(uuid=uuid, **common, children=children)

    common = dict(
        kind=KindEvent.create,
        kind_obj=KindObject.event,
        uuid_obj="666-666-666",
        uuid_user="test-flattened",
        detail="TEST FLATTENED",
        api_version=__version__,
        api_origin="TestEvent",
    )

    # Traversing the below tree depth first should reorder the letters
    B = make("B", [make("C"), make("D"), make("E", [make("F"), make("G")])])
    H = make(
        "H",
        [make("I", [make("J"), make("K", [make("L"), make("M", [make("N")])])])],
    )
    A = make("A", [B, H])

    nodechars = "ABCDEFGHIJKLMN"
    uuids = {
        node.uuid: make_uuid(nodechars[index])
        for index, node in enumerate(A.flattened())
    }

    assert list(uuids) == list(uuids.values())


@pytest.mark.parametrize("count", list(range(5)))
class TestRelationships:
    """It is important to note that the primary purpose of configuring the
    object relationships is to ensure correct deletion cascading, thus why
    all relationships load data that might be pending deletion, etc.

    When this is not configured properly, it is easy to get strange and hard
    to debug sqlalchemy errors as a result.

    Please see

    .. code:: txt

        https://docs.sqlalchemy.org/en/20/orm/cascades.html#cascade-delete-many-to-many

    """

    # @pytest.mark.parametrize(
    #     "dummy_disposable, count",
    #     [(None, k) for k in range(3)],
    #     indirect=["dummy_disposable"],
    # )
    def test_collection_deletion(self, dummy_disposable: DummyProvider, count: int):
        dummy = dummy_disposable
        collections, session = dummy.get_collections(15), dummy.session
        msg_fmt = "`{}` of `{}` `{}` were not deleted. Check ORM relationships"

        n_empty_assignments = 0
        for collection in collections:
            q_assignment = collection.q_select_assignment(exclude_deleted=False)
            assignments = session.scalars(q_assignment)
            uuid_assignment, uuid_document = zip(
                *((item.uuid, item.uuid_document) for item in assignments)
            )

            if not (n_assignment := len(uuid_assignment)):
                n_empty_assignments += 1

            # --------------------------------------------------------------- #
            dummy.session.delete(collection)
            session.commit()

            # NOTE: Assignments should have been deleted.
            q_assignment_remaining = select(func.count(Assignment.uuid)).where(
                Assignment.uuid.in_(uuid_assignment)
            )
            n_assignment_remaining = session.scalar(q_assignment_remaining)

            if n_assignment_remaining:
                raise AssertionError(
                    msg_fmt.format(n_assignment_remaining, n_assignment, "assignments")
                )

            # NOTE: No documents should have been deleted.
            q_documents_remaining = select(func.count(Document.uuid)).where(
                Document.uuid.in_(uuid_document)
            )
            n_documents_remaining = session.scalar(q_documents_remaining)
            assert n_documents_remaining is not None
            print(uuid_document)

            if n_documents_remaining != n_assignment:
                raise AssertionError(
                    f"`{n_assignment - n_documents_remaining}` of `{n_assignment}` "
                    "`documents` were deleted. No `documents` should have "
                    "been deleted."
                )

        if n_empty_assignments:
            raise AssertionError("All collections have empty assignments.")

    # @pytest.mark.parametrize(
    #     "dummy_disposable, count",
    #     [(None, k) for k in range(3)],
    #     indirect=["dummy_disposable"],
    # )
    def test_document_deletion(self, dummy_disposable: DummyProvider, count: int):
        dummy = dummy_disposable
        documents, session = dummy.get_documents(level=Level.view, n=15), dummy.session
        uuid_column = literal_column("uuid")
        msg_fmt = "`{}` of `{}` `{}` were not deleted. Check ORM relationships"
        msg_fmt += " and queries."

        n_empty_grants, n_empty_assignments = 0, 0
        for document in documents:
            # NOTE: Get uuids of of users, edits, and collections before
            #       deletion.
            q_grant_uuids = document.q_select_grants(
                exclude_deleted=False,
                exclude_pending=False,
            )
            q_grant_uuids = select(uuid_column).select_from(q_grant_uuids.subquery())

            if not (uuid_grant := set(session.scalars(q_grant_uuids))):
                n_empty_grants += 1
                continue

            q_assignment = document.q_select_assignment(
                exclude_deleted=False,
            )
            assignments = tuple(session.scalars(q_assignment))
            if not assignments:
                n_empty_assignments += 1
                continue

            uuid_assignment, uuid_collection = (
                set(uuids)
                for uuids in zip(
                    *((item.uuid, item.uuid_collection) for item in assignments)
                )
            )
            q_cols_remaining = select(func.count(Collection.uuid)).where(
                Collection.uuid.in_(uuid_collection)
            )

            # NOTE: Because there are not dummies.
            # q_edit_uuids = select(Edit.uuid).where(Edit.id_document == document.id)
            # uuid_edit = set(session.scalars(q_edit_uuids))

            # --------------------------------------------------------------- #
            dummy.session.delete(document)
            session.commit()

            # NOTE: Count the number of remaining associated objects.
            q_grant_remaining = select(func.count(Grant.uuid)).where(
                Grant.uuid.in_(uuid_grant)
            )
            if n := session.scalar(q_grant_remaining):
                msg = msg_fmt.format(n, len(uuid_grant), "grants")
                raise AssertionError(msg)

            q_assignment_remaining = select(func.count(Assignment.uuid)).where(
                Assignment.uuid.in_(uuid_assignment)
            )
            if m := session.scalar(q_assignment_remaining):
                msg = msg_fmt.format(m, len(uuid_grant), "assignments")
                raise AssertionError(msg)

                # q_edit_remaining = select(func.count(Edit.uuid)).where(
                # Edit.uuid.in_(uuid_edit)
                # )
                # if p := session.scalar(q_edit_remaining):
                #     msg = msg_fmt.format(p, len(uuid_edit), "edits")
                raise AssertionError(msg)

            # NOTE: Verify that documents were not deleted.
            q_cols_remaining = select(func.count(Collection.uuid)).where(
                Collection.uuid.in_(uuid_collection)
            )
            n_cols_remaining = session.scalar(q_cols_remaining)
            if n_cols_remaining != (n_cols := len(uuid_collection)):
                raise AssertionError(
                    f"`{n_cols_remaining}` of `{n_cols}` collections were "
                    "deleted. No collections should have been deleted."
                )

        if n_empty_grants == len(documents):
            raise AssertionError("All documents have empty grants.")

        if n_empty_assignments == len(documents):
            raise AssertionError("All documents have empty assignments.")

    def test_user_deletion_documents(
        self, dummy_handler: DummyHandler, session: Session, count: int
    ):
        n_empty_grants = 0
        for dummy in (DummyProvider(dummy_handler.config, session) for _ in range(5)):
            user = dummy.user
            q_grants = user.q_select_grants(exclude_deleted=False)
            grants = dummy.session.scalars(q_grants)

            uuid_grant, uuid_document = zip(
                *((item.uuid, item.uuid_document) for item in grants)
            )

            if n_empty_grants:
                n_empty_grants += 1

            q_uniq = user.q_select_documents(
                uuid_document,
                exclude_deleted=False,
                n_owners=1,
                n_owners_levelsets=True,
            )
            uuids_docs_uniq = set(item.uuid for item in session.scalars(q_uniq))
            assert uuids_docs_uniq.issubset(uuid_document)

            session.delete(user)
            session.commit()

            # NOTE: Verify that grants have been deleted.
            q_grant_remaining = select(func.count(Grant.uuid)).where(
                Grant.uuid.in_(uuid_grant)
            )
            n_grant_remaining = session.scalar(q_grant_remaining)
            assert not n_grant_remaining

            # NOTE: Verify that only orphan documents have been deleted.
            q_docs_remaining = select(func.count(Document.uuid)).where(
                Document.uuid.in_(uuids_docs_uniq)
            )
            n_docs_remaining = session.scalar(q_docs_remaining)
            assert n_docs_remaining == 0

            dummy.dispose()

    def test_user_deletion_collections(
        self, dummy_handler: DummyHandler, session: Session, count: int
    ):
        n_no_collections = 0
        for _ in range(0, 3):
            dummy = DummyProvider(dummy_handler.config, session)
            user = dummy.user
            uuid_collections = set(
                session.scalars(
                    select(Collection.uuid).where(Collection.id_user == user.id)
                )
            )
            if not len(uuid_collections):
                n_no_collections += 1
                continue

            session.delete(user)
            session.commit()
            session.expire_all()

            q_cols_remaining = select(func.count(Collection.uuid)).where(
                Collection.uuid.in_(uuid_collections)
            )
            n_cols_remaining = session.scalar(q_cols_remaining)
            assert not n_cols_remaining

            dummy.dispose()

        if n_no_collections == 2:
            msg = "All users had empty `collections`."
            raise AssertionError(msg)

        # NOTE: Should fail since dummies do not generate edits.
        # @pytest.mark.xfail
        # def test_user_deletion_edits(self, auth: Auth, session: Session, count: int):
        #     n_no_edits = 0
        #     for dummy in (DummyProvider(auth, session) for _ in range(10)):
        #         user = dummy.user
        #
        #         uuid_edits = set(
        #             session.scalars(select(Edit.uuid).where(Edit.id_user == user.id))
        #         )
        #         if not (n_edits := len(uuid_edits)):
        #             n_no_edits += 1
        #             continue
        #
        #         session.delete(user)
        #         session.commit()
        #
        #         q_edits_remaining = select(func.count(Edit.uuid)).where(
        #             Edit.uuid.in_(uuid_edits)
        #         )
        #         n_edits_remaining = session.scalar(q_edits_remaining)
        #         assert n_edits_remaining == n_edits
        #
        #         dummy.dispose()
        #
        #     if n_no_edits == 2:
        #         raise AssertionError("All dummies had empty `edits`.")
        #
        # NOTE: Not necessary. But definitely nice to have.
        # def test_dummy_dispose(self, dummy_disposable: DummyProvider, count: int = 1):
        #     """Verify that `DummyProvider.dispose` cleans up a dummy as
        #     desired."""
        #
        #     dummy, user, session = dummy_disposable, dummy_disposable.user, dummy_disposable.session
        #     # uuid_user = user.uuid
        #
        #     # NOTE: Get documents. Only orphaned documents should be deleted.
        #     q_uuid_doc = user.q_select_documents(exclude_deleted=False)
        #     uuid_doc = set(item.uuid for item in session.scalars(q_uuid_doc))
        #
        #     q_uuid_document_uniq = user.q_select_documents(
        #         exclude_deleted=False,
        #         n_owners=1,
        #         n_owners_levelsets=True,
        #         kind_select=KindSelect.uuids,
        #     )
        #     uuid_doc_uniq = set(item.uuid for item in session.scalars(q_uuid_document_uniq))
        #     assert uuid_doc_uniq.issubset(uuid_doc)
        #
        #     # NOTE: Get collections and edits. Collections should be deleted,
        #     #       edits should not be deleted unless they belong to one of the
        #     #       above documents.
        #     q_uuid_edit = select(Edit.uuid).where(Edit.id_user == user.id)
        #     uuid_edit = set(session.scalars(q_uuid_edit))
        #
        #     q_uuid_edit_uniq = q_uuid_edit.join(Document).where(
        #         Document.uuid.in_(uuid_doc_uniq)
        #     )
        #     uuid_edit_uniq = set(session.scalars(q_uuid_edit_uniq))
        #
        #     q_uuid_collection = select(Collection.uuid).where(Collection.id_user == user.id)
        #     uuid_collection = set(session.scalars(q_uuid_collection))
        #
        #     session.delete(user)
        # session.commit()


@pytest.mark.parametrize("count", list(range(25)))
class TestUser:
    def test_q_select_documents(
        self, dummy_handler: DummyHandler, session: Session, count: int
    ):
        dummy = DummyProvider(dummy_handler.config, session)
        dummy.info_mark_used(f"test_q_select_documents-{count}")
        user, session = dummy.user, dummy.session
        fn = user.q_select_documents

        docs: Tuple[Document, ...]
        grants: Tuple[Grant, ...]
        kwargs: Dict[str, Any]

        def get_grants(docs: Resolvable[Document]) -> Tuple[Grant, ...]:
            uuid_document = Document.resolve_uuid(session, docs)
            q = select(Grant).join(Document)
            q = q.where(Document.uuid.in_(uuid_document), Grant.id_user == user.id)
            return tuple(session.scalars(q))

        def uuids(docs) -> Set[str]:
            return Document.resolve_uuid(session, docs)

        check = Check(session)

        # ------------------------------------------------------------------- #
        with pytest.raises(ValueError) as err:
            fn(exclude_pending=True, pending=True)

        msg = "`pending` and `exclude_pending` cannot both be `True`."
        assert str(err.value) == msg

        kwargs = dict(exclude_pending=False, pending=True)
        dummy.randomize_grants()
        docs = tuple(session.scalars(q := fn(**kwargs).limit(10)))
        util.sql(session, q)
        if not len(docs):
            msg = "Could not find pending documents for dummy `{}`."
            raise AssertionError(msg.format(dummy.user.uuid))

        assert len(grants := get_grants(uuid_document := uuids(docs))) == len(docs)

        check.all_(grants, pending=True, deleted=False)
        docs_by_uuid = tuple(session.scalars(fn(uuid_document)))
        assert not len(docs_by_uuid)  # NOTE: `pending=False` by default.

        # ------------------------------------------------------------------- #

        n_mt = 0
        for pending_from in list(PendingFrom):
            kwargs = dict(pending_from=pending_from, pending=None, exclude_pending=True)
            docs = tuple(session.scalars(fn(**kwargs).limit(10)))
            if not (n := len(docs)):
                # fmt = "Could not find docs pending from `{}` for dummy `{}`."
                # msg = fmt.format(pending_from.name, dummy.user.uuid)
                # raise AssertionError(msg)
                n_mt += 1
                continue

            assert len(grants := get_grants(docs)) == len(docs)

            # NOTE: Getting these documents using their uuids should not
            uuid_document = Document.resolve_uuid(session, docs)
            docs_by_uuid = tuple(session.scalars(Document.q_uuid(uuid_document)))
            assert len(docs_by_uuid) == n

            (
                check.all_(
                    grants,
                    pending=False,
                    pending_from=pending_from,
                    deleted=False,
                )
                .uuids(
                    KindObject.document,
                    {gg.uuid_document for gg in grants},
                    uuid_document,
                )
                .uuids(
                    KindObject.document,
                    docs,
                    docs_by_uuid,
                )
            )

        if n_mt == 3:
            raise AssertionError("All `pending_from` filtered data was empty.")

        # ------------------------------------------------------------------- #

        for level in list(Level):
            kwargs = dict(level=level)
            docs = tuple(session.scalars(fn(**kwargs)))
            uuid_document = uuids(docs)
            assert len(grants := get_grants(docs)) == len(docs)

            (
                check.all_(
                    grants,
                    level=lambda grant: grant.level.value < level.value,
                    deleted=False,
                )
                .uuids(
                    KindObject.document,
                    docs,
                    tuple(session.scalars(fn(uuid_document))),
                )
                .uuids(
                    KindObject.document,
                    {gg.uuid_document for gg in grants},
                    uuid_document,
                )
            )

            # NOTE: Verify that count and uuids work correctly
            kwargs.update(kind_select=KindSelect.count)
            docs_count = session.scalar(q := fn(**kwargs))
            assert docs_count == len(uuid_document)

            kwargs.update(kind_select=KindSelect.uuids)
            uuid_document_again = set(session.scalars(fn(**kwargs)))
            assert uuid_document == uuid_document_again

            # NOTE: The same as above but with level levelsets.
            kwargs = dict(level=level, level_levelsets=True)
            docs = tuple(session.scalars(fn(**kwargs)))
            uuid_document = uuids(docs)
            assert len(docs) == len(grants := get_grants(docs))

            (
                check.all_(grants, level=level, deleted=False)
                .uuids(
                    KindObject.document,
                    docs,
                    tuple(session.scalars(fn(uuid_document))),
                )
                .uuids(
                    KindObject.document,
                    {gg.uuid_document for gg in grants},
                    uuid_document,
                )
            )

            # NOTE: Verify that count and uuids work correctly
            kwargs.update(kind_select=KindSelect.count)
            docs_count = session.scalar(q := fn(**kwargs))
            util.sql(session, q)
            assert docs_count == len(uuid_document)

            kwargs.update(kind_select=KindSelect.uuids)
            uuid_document_again = set(session.scalars(fn(**kwargs)))
            assert uuid_document == uuid_document_again

        # ------------------------------------------------------------------- #

        uuid_document = set()
        for n_owners in range(1, 15):
            # Add uniquely owned doc
            doc = Document(
                content=dict(
                    tags=["test_models.TestUser.test_q_select_documents"],
                    tainted=True,
                ),
                name=f"test-q-select-models-{secrets.token_urlsafe(8)}",
                description="test",
                deleted=False,
            )
            session.add(doc)
            session.commit()
            session.expire(doc)

            grant = Grant(
                level=Level.own,
                pending_from=PendingFrom.created,
                pending=False,
                deleted=False,
                id_user=dummy.user.id,
                id_document=doc.id,
            )

            session.add(grant)
            session.commit()
            session.expire_all()

            uuid_document.add(doc.uuid)
            kwargs = dict(n_owners=1, document_uuids=uuid_document)
            docs = tuple(session.scalars(q := fn(**kwargs)))

            q = user.q_select_documents_exclusive(uuid_document)
            docs_exclusive = tuple(session.scalars(q))

            assert len(grants := get_grants(docs)) == len(docs) == n_owners
            (
                check.all_(grants, deleted=False)
                .uuids(
                    KindObject.document,
                    {gg.uuid_document for gg in grants},
                    uuid_document,
                )
                .uuids(KindObject.document, docs, uuid_document)
                .uuids(KindObject.document, docs, docs_exclusive)
            )

            # NOTE: Verify that count and uuids are not allowed in this mode.
            with pytest.raises(ValueError) as err:
                kwargs.update(kind_select=KindSelect.count)
                fn(**kwargs)

            with pytest.raises(ValueError) as err:
                kwargs.update(kind_select=KindSelect.uuids)
                fn(**kwargs)
