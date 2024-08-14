# =========================================================================== #
from http import HTTPMethod

import pytest
from fastapi import HTTPException

# --------------------------------------------------------------------------- #
from captura.controllers.base import (
    BaseController,
    BaseResolved,
    KindData,
    ResolvedAssignmentDocument,
    ResolvedDocument,
    ResolvedUser,
)
from captura.models import uuids
from captura.schemas import mwargs
from simulatus import DummyProvider


def test_UuidSetFromModel(dummy: DummyProvider):
    docs = dummy.get_documents(n=2, other=True)
    uuids_expected = uuids(docs)
    assert len(docs) == 2

    res = mwargs(ResolvedDocument, documents=docs, token_user_grants={})
    assert res.documents == docs
    assert res.uuid_documents == uuids_expected


def test_UuidFromModel(dummy: DummyProvider):
    (doc,) = dummy.get_documents(other=True, n=1)
    uuid_doc_expected = doc.uuid

    collections = dummy.get_collections(other=True, n=10)
    uuid_col_expected = uuids(collections)

    assert len(collections) == 10
    res = mwargs(
        ResolvedAssignmentDocument,
        document=doc,
        collections=collections,
        assignments=dict(),
    )
    assert res.uuid_collections == uuid_col_expected
    assert res.uuid_document == uuid_doc_expected
    assert isinstance(res.assignments, dict)
    assert isinstance(res.uuid_assignments, set)
    assert isinstance(res.uuid_document, str)
    assert isinstance(res.uuid_collections, set)


def test_base_controller(dummy: DummyProvider):
    dd = dummy
    base = BaseController(dd.session, None, HTTPMethod.GET)
    with pytest.raises(HTTPException) as err:
        base.token

    assert err.value.detail == "Token required."

    with pytest.raises(HTTPException) as err:
        base.token_user

    assert err.value.detail == "Token required."

    with pytest.raises(ValueError) as err:
        BaseController(dd.session, None, "Foo")

    assert str(err.value) == "Invalid input `Foo` for parameter `method`."

    with pytest.raises(ValueError) as err:
        BaseController(dd.session, "blahblah", "GET")  # type: ignore

    assert str(err.value) == "Invalid input `blahblah` for parameter `token`."

    BaseController(dd.session, dd.token, HTTPMethod.GET)


class TestBaseResolved:
    def test_init_subclass(self):  # , default: DummyProvider):
        # dd = default
        def create_cls(**namespace):
            return type("Foo", (BaseResolved,), namespace)

        # Bad kind
        with pytest.raises(ValueError) as err:
            create_cls(kind="raboof")

        # Should fail, registry already has such an entry.
        with pytest.raises(ValueError) as err:
            create_cls(kind=KindData.user)

        assert str(err.value).startswith("`registry` already has a resolved class ")

        # Should be able to get the actual class
        res = BaseResolved.get(KindData.user)
        assert res == ResolvedUser


class TestBaseResolvedPrimary:
    # def test_init_subclass_base(self, default: DummyProvider):
    #
    #     dd = default

    # def test_instance_methods(self, dummy: DummyProvider):
    #     dd = dummy
    #     data = dd.data(KindData.user)
    #     assert isinstance(data.data, ResolvedUser)
    #     res = data.data
    #
    #     assert res.targets() == res.users

    def test_mt(self):
        mt = ResolvedUser.empty()
        assert not len(mt.users)
        assert mt.err_nonempty() is None


# class TestResolvedSecondary:
#     def test_instance_methods(self, dummy: DummyProvider):
#         dd = dummy
#         data = dd.data(KindData.grant_user)
#         assert isinstance(data.data, ResolvedGrantUser)
#         res = data.data
#
#         assert res.target == res.documents
#         assert res.source == res.user
#         assert res.assoc == res.grants
