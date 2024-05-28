import pytest
from sqlalchemy import select

# --------------------------------------------------------------------------- #
from app.controllers.base import (
    Data,
    KindData,
    ResolvedCollection,
    ResolvedDocument,
    ResolvedEvent,
)
from app.models import Assignment, Collection, Document, Event, Grant, KindObject
from dummy import DummyProvider


class TestDelete:

    def test_delete_collection(self, dummy: DummyProvider):
        delete = dummy.visability(
            {KindObject.collection}, public=False, deleted=False
        ).delete(api_origin=f"{__file__}::test_delete_user", force=False)
        assert delete.force is False

        data: Data[ResolvedCollection] = dummy.data(KindData.collection)
        assert isinstance(data, Data)
        assert isinstance(data.data, ResolvedCollection)
        assert data.data.collections is not None
        assert data.event is None
        assert not len(data.children)

        delete.collection(data)
        assert data.event is not None
        assert data.event.uuid is None  # No commit yet.

        data.commit(delete.session)
        assert data.event.uuid is not None

        delete.session.expire_all()
        if n := len(tuple(cc for cc in data.data.collections if not cc.deleted)):
            msg = f"`{n}` of `{len(data.data.collections)}` collections not deleted."
            raise AssertionError(msg)

        q_assignments_deleted = (
            select(Assignment)
            .join(Collection)
            .where(Collection.uuid.in_(set(cc.uuid for cc in data.data.collections)))
        )
        assignments_deleted = tuple(dummy.session.scalars(q_assignments_deleted))
        if n := len(tuple(aa for aa in assignments_deleted if not aa.deleted)):
            msg = f"`{n}` of `{len(data.data.assignments)}` assignments not deleted."
            raise AssertionError(msg)

        # ------------------------------------------------------------------- #

        delete.force = True
        data_force: Data[ResolvedCollection] = dummy.data(KindData.collection)
        assert len(data_force.data.collections)
        assert data_force.event is None

        delete.collection(data_force)
        assert data_force.event is not None
        assert data_force.event.uuid is None

        data_force.commit(delete.session)
        assert data_force.event.uuid is not None

        uuid_collections = set(cc.uuid for cc in data_force.data.collections)
        q_collections = select(Collection).where(Collection.uuid.in_(uuid_collections))
        collections_remaining = tuple(dummy.session.scalars(q_collections))
        assert not len(collections_remaining), "Collections should have been deleted."

        q_assignments = (
            select(Assignment)
            .join(Collection)
            .where(Collection.uuid.in_(uuid_collections))
        )
        assignments = tuple(dummy.session.scalars(q_assignments))
        assert not len(assignments), "Collections should have no remaining assignments."

    def test_delete_document(self, dummy: DummyProvider):
        delete = dummy.visability(
            {KindObject.document}, public=False, deleted=False
        ).delete(api_origin=f"{__file__}::test_delete_document", force=False)

        assert delete.force is False

        data: Data[ResolvedDocument] = dummy.data(KindData.document)
        assert isinstance(data, Data)
        assert isinstance(data.data, ResolvedDocument)
        assert data.data.documents is not None
        assert data.event is None
        assert not len(data.children)

        delete.document(data)
        assert data.event is not None
        assert data.event.uuid is None  # No commit yet.

        data.commit(delete.session)
        assert data.event.uuid is not None

        uuid_document = set(dd.uuid for dd in data.data.documents)
        # delete.session.expire_all()

        documents_expect_deleted = data.data.documents

        if n := len(tuple(dd for dd in documents_expect_deleted if not dd.deleted)):
            m = len(documents_expect_deleted)
            msg = f"`{n}` of `{m}` documents not deleted."
            raise AssertionError(msg)

        q_assignments = (
            select(Assignment).join(Document).where(Document.uuid.in_(uuid_document))
        )
        assignments = tuple(dummy.session.scalars(q_assignments))
        if n := len(tuple(aa for aa in assignments if not aa.deleted)):
            msg = f"`{n} of `{len(assignments)}` assignments not deleted."
            raise AssertionError(msg)

        q_grants = select(Grant).join(Document).where(Document.uuid.in_(uuid_document))
        grants = tuple(dummy.session.scalars(q_grants))
        if n := len(tuple(gg for gg in grants if not gg.deleted)):
            msg = f"`{n}` of `{len(assignments)}` grants not deleted."
            raise AssertionError(msg)

        # ------------------------------------------------------------------- #

        data_force: Data[ResolvedDocument] = dummy.data(KindData.document)
        assert isinstance(data_force, Data)
        assert isinstance(data_force.data, ResolvedDocument)
        assert data_force.data.documents is not None
        assert data_force.event is None
        assert not len(data_force.children)

        delete.force = True
        delete.document(data_force)
        assert data_force.event is not None
        assert data_force.event.uuid is None  # No commit yet.

        data_force.commit(delete.session)
        assert data_force.event.uuid is not None

        uuid_document = set(dd.uuid for dd in data_force.data.documents)
        if n := len(Document.resolve_uuid(dummy.session, uuid_document)):
            raise ValueError(f"`{n}` documents not deleted.")

        q_assignments = (
            select(Assignment).join(Document).where(Document.uuid.in_(uuid_document))
        )
        assignments = tuple(dummy.session.scalars(q_assignments))
        if n := len(tuple(aa for aa in assignments if not aa.deleted)):
            msg = f"`{n} of `{len(assignments)}` assignments not deleted."
            raise AssertionError(msg)

        q_grants = select(Grant).join(Document).where(Document.uuid.in_(uuid_document))
        grants = tuple(dummy.session.scalars(q_grants))
        if n := len(tuple(gg for gg in grants if not gg.deleted)):
            msg = f"`{n}` of `{len(assignments)}` grants not deleted."
            raise AssertionError(msg)

    def test_delete_event(self, dummy: DummyProvider):
        delete = (
            dummy.visability({KindObject.event}, deleted=True, public=False)
            .refresh()
            .delete(api_origin=f"{__file__}::test_delete_event")
        )
        data: Data[ResolvedEvent] = dummy.data(KindData.event)

        assert isinstance(data, Data)
        assert isinstance(data.data, ResolvedEvent)
        assert len(data.data.events)

        # ------------------------------------------------------------------- #

        delete.event(data)

        assert data.event is not None
        assert data.event.uuid is None  # No commit yet.

        data.commit(delete.session)
        assert data.event.uuid is not None

        events = set(ee.uuid for ee in data.data.events if not ee.deleted)
        if n := len(events):
            m = len(data.data.events)
            raise AssertionError(f"`{n}` of `{m}` events remaining.")

        # ------------------------------------------------------------------- #

        delete.force = True
        data_force: Data[ResolvedEvent] = dummy.data(KindData.event)
        delete.event(data_force)

        assert data_force.event is not None
        assert data_force.event.uuid is None

        data_force.commit(delete.session)
        assert data_force.event.uuid is not None

        uuid_event = set(ee.uuid for ee in data_force.data.events)
        events = Event.resolve(dummy.session, uuid_event)
        if n := len(events):
            m = len(data.data.events)
            raise AssertionError(f"`{n}` of `{m}` events remaining.")
