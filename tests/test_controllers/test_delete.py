
import pytest
from app.controllers.base import (Data, KindData, ResolvedCollection,
                                  ResolvedDocument)
from app.models import Assignment, Collection, KindObject
from app.schemas import mwargs
from sqlalchemy import false, select
from tests.dummy import Dummy


class TestDelete:
    @pytest.fixture(autouse=True, scope="session")
    def fixtures(self, load_tables) -> None:
        return

    def test_delete_collection(self, dummy: Dummy):

        delete = dummy.visability(
            {KindObject.collection}, public=False, deleted=False
        ).delete(api_origin=f"{__file__}::test_delete_user", force=False)
        assert delete.force is False

        data: Data[ResolvedCollection] = dummy.data(KindData.collection)
        assert isinstance(data, Data)
        assert isinstance(data.data, ResolvedCollection)
        assert data.data.collections is not None
        # assert data.data.assignments is not None
        assert data.event is None
        assert not len(data.children)
        
        delete.collection(data)
        # assert data.data.
        assert data.event is not None
        assert data.event.uuid is None # No commit yet.
        
        data.commit(delete.session)
        assert data.event.uuid is not None
        
        delete.session.expire_all()
        if n := len(tuple(cc for cc in data.data.collections if not cc.deleted)):
            msg = f"`{n}` of `{len(data.data.collections)}` collections not deleted."
            raise AssertionError(msg)

        q_assignments_deleted = select(Assignment).join(Collection).where(
            Collection.uuid.in_(set(cc.uuid for cc in data.data.collections))
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
        input()

        data_force.commit(delete.session)
        assert data_force.event.uuid is not None

        uuid_collections = set(cc.uuid for cc in data_force.data.collections)
        q_collections = select(Collection).where(Collection.uuid.in_(uuid_collections))
        collections_remaining = tuple(dummy.session.scalars(q_collections))
        assert not len(collections_remaining), "Collections should have been deleted."

        q_assignments = select(Assignment).join(Collection).where(Collection.uuid.in_(uuid_collections))
        assignments = tuple(dummy.session.scalars(q_assignments))
        assert not len(assignments), "Collections should have no remaining assignments."


    def test_delete_document(self, dummy: Dummy):
        ...






