import inspect
from http import HTTPMethod
from typing import Callable, Set, Tuple, Type

import pytest
from app import util
from app.models import (Assignment, AssocUserDocument, Collection, Document,
                        Grant, KindEvent, KindObject, Singular, User)
from app.schemas import EventSchema
from app.views.base import Data, DataResolvedAssignment, DataResolvedGrant
from app.views.create import Upsert
from app.views.delete import AssocData, Delete
from sqlalchemy import Delete as sqaDelete
from sqlalchemy import Update, update
from sqlalchemy.orm import Session, make_transient
from sqlalchemy.orm.attributes import Event
from tests.test_views import util

TEST_DETAIL = "From `test_delete.py`."
TEST_API_ORIGIN = "./tests/test_controllers/test_delete.py"


@pytest.fixture
def delete(session: Session) -> Delete:
    return Delete(
        session,
        dict(uuid="000-000-000"),
        HTTPMethod.POST,
        detail=TEST_DETAIL,
        api_origin=TEST_API_ORIGIN,
    )


def as_data(
    delete: Delete | Upsert,
    T_source: Type,
    uuid_source: str,
    T_target: Type,
    uuid_target: Set[str],
    T_assoc: Type,
    uuid_assoc: Set[str],
) -> Data:

    source = T_source.if_exists(delete.session, uuid_source)
    targets = T_target.if_many(delete.session, uuid_target)
    name_source = KindObject(T_source.__tablename__).name
    name_target = KindObject(T_target.__tablename__).name
    name_assignment = KindObject(T_assoc.__tablename__).name
    data_resolved = {
        name_source: source,
        Singular(name_target).name: targets,
        "kind": f"{name_assignment}_{name_source}",
    }
    data = Data(data=data_resolved)  # type: ignore[generalType]
    return data


CASES_ASSOCS = [
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
]

class BaseTestAssoc:
    # ----------------------------------------------------------------------- #
    # Fixtures

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

    def check_event(
        self,
        delete: Delete | Upsert,
        assoc_data: AssocData,
        data: DataResolvedAssignment | DataResolvedGrant,
        _event: Event | None = None
    ) -> EventSchema:
        assert data.event is not None
        expect_common = delete.event_common
        event = EventSchema.model_validate(data.event if _event is None else _event)

        util.event_compare(event, expect_common)
        assert event.kind_obj == data.data.kind_source
        assert event.uuid_obj == data.data.uuid_source

        match delete:
            case Upsert(force=force):
                uuid_target_expected = data.data.uuid_target.copy()
                if not force:
                    uuid_target_expected -= assoc_data.uuid_target_active
                uuid_assoc_expected = None
            case Delete(force=force):
                uuid_target_expected = assoc_data.uuid_target_active.copy()
                uuid_assoc_expected = assoc_data.uuid_assoc_active.copy()
                if force:
                    uuid_target_expected |= assoc_data.uuid_target_deleted 
                    uuid_assoc_expected |= assoc_data.uuid_assoc_deleted
            case bad:
                raise ValueError(f"Invalid value `{bad}` for `delete`.")


        for item in event.children:
            util.event_compare(item, expect_common)
            assert len(item.children) == 1
            assert item.kind_obj == data.data.kind_target
            assert item.uuid_obj in uuid_target_expected

            subitem, *_ = item.children
            util.event_compare(subitem, expect_common)
            assert len(subitem.children) == 0
            assert subitem.kind_obj == data.data.kind_assoc
            if uuid_assoc_expected:
                assert subitem.uuid_obj in uuid_assoc_expected

        return event

    def check_mthd(self, delete: Delete | Upsert, data: DataResolvedAssignment | DataResolvedGrant,) -> Callable[
        [Data], 
        Tuple[
            DataResolvedGrant | DataResolvedAssignment,
            AssocData,
            Update[Assignment] | sqaDelete[Assignment],
            Type[Assignment],
        ]
    ]:

        # Get method (name should match data kind).
        if (mthd := getattr(delete, data.kind, None)) is None:
            msg = f"Expected attribute `{data.kind}` of `Delete`."
            raise AssertionError(msg)
        elif not callable(mthd):
            msg = f"`Delete.{data.kind}` must be callable."
            raise AssertionError(msg)

        sig = inspect.signature(mthd)
        if sig.parameters.get("data") is None:
            raise AssertionError("Missing parameter `data`.")
        elif len(sig.parameters) == 2 and "self" not in sig.parameters:
            msg = "Expected exactly two parameters, `self` and `data`."
            raise AssertionError(msg)
        elif (return_t := sig.return_annotation) == Data:
            msg = f"Expect return annotation to be `Data`, got `{return_t}`."
            raise AssertionError(msg)

        # Make sure that the corresponding method exists.
        a_mthd = getattr(delete, f"a_{data.kind}")
        if not callable(a_mthd):
            msg = f"`Delete.{data.kind}`s signature should match signature of "
            msg += f"`Access.{data.kind}`."
            raise AssertionError(msg)

        return mthd

@pytest.mark.parametrize(
    "delete, T_source, uuid_source, T_target, uuid_target, T_assoc, uuid_assoc",
    CASES_ASSOCS,
    indirect=["delete"],
)
class TestDeleteAssoc(BaseTestAssoc):

    # ----------------------------------------------------------------------- #
    # Tests

    def test_split_assoc(
        self,
        delete: Delete,
        T_source: Type,
        uuid_source: str,
        T_target: Type,
        uuid_target: Set[str],
        T_assoc: Type,
        uuid_assoc: Set[str],
    ) -> None:
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

    @pytest.mark.parametrize("force", [True, False])
    def test_try_force(
        self,
        delete: Delete,
        T_source: Type,
        uuid_source: str,
        T_target: Type,
        uuid_target: Set[str],
        T_assoc: Type,
        uuid_assoc: Set[str],
        force: bool
    ) -> None:

        session = delete.session
        delete.force = force

        assocs = T_assoc.resolve(session, uuid_assoc)
        assoc1, *_ = assocs
        assoc1.deleted = True
        session.add(assoc1)
        session.commit()

        # data = Data(data=data_resolved)  # type: ignore[generalType]
        data = as_data(
            delete, T_source, uuid_source, T_target, uuid_target, T_assoc, uuid_assoc
        )
        res = delete.try_force(data)

        assert len(res) == 4
        assoc_data, assoc_rm, q_del, T_assoc_returned = res
        assert T_assoc == T_assoc_returned

        uuid_assoc_rm: Set[str] = T_assoc.resolve_uuid(session, assoc_rm)

        assert isinstance(assoc_data, AssocData)
        assert all(uuid in uuid_assoc for uuid in assoc_data.uuid_assoc_active)
        assert all(uuid in uuid_target for uuid in assoc_data.uuid_target_active)
        assert len(assoc_data.uuid_target_deleted) == 1
        assert len(assoc_data.uuid_assoc_deleted) == 1

        assert isinstance(assoc_rm, tuple)
        if force:
            assert uuid_assoc_rm == uuid_assoc
            assert isinstance(q_del, sqaDelete)
            assert len(assoc_rm) == len(uuid_assoc)
        else:
            assert uuid_assoc_rm.issubset(uuid_assoc)
            assert assoc1.uuid not in uuid_assoc_rm
            assert isinstance(q_del, Update)
            assert len(assoc_rm) == len(uuid_assoc) - 1

    def test_many_many(
        self,
        delete: Delete,
        T_source: Type,
        uuid_source: str,
        T_target: Type,
        uuid_target: Set[str],
        T_assoc: Type,
        uuid_assoc: Set[str],
    ):
        data = as_data(
            delete, T_source, uuid_source, T_target, uuid_target, T_assoc, uuid_assoc
        )
        session = delete.session
        assocs_init = T_assoc.resolve(session, uuid_assoc)
        mthd = self.check_mthd(delete, data)

        # Run the method without force
        assert data.event is None
        assert delete.force is False
        assoc_data, *_, T_assoc_recieved = delete.try_force(data)
        _ = mthd(data)
        assert T_assoc_recieved == T_assoc
        self.check_event(delete, assoc_data, data)

        # Check the changes in the database. Assocs should be removed.
        assocs_found = T_assoc.resolve(session, uuid_assoc)
        uuid_assocs_found = T_assoc.resolve_uuid(session, assocs_found)

        bad = tuple(uu for uu in uuid_assoc if uu not in uuid_assocs_found)
        if bad:
            msg = f"The following assocs could not be found: `{bad}`."
            raise AssertionError(msg)
        elif bad := tuple(assoc.uuid for assoc in assocs_found if not assoc.deleted):
            msg = f"The following assocs are not deleted: `{bad}`."
            raise AssertionError(msg)

        # Run the method with force
        delete.force = True
        _ = mthd(data)
        self.check_event(delete, assoc_data, data)
        assocs = T_assoc.resolve(session, uuid_assoc)
        assert not len(assocs)

        session.add_all(make_transient(item) or item for item in assocs_init)
        session.commit()
