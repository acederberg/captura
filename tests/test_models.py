# =========================================================================== #
import pytest
from typing import List

from sqlalchemy import func, literal_column, select


# --------------------------------------------------------------------------- #
from app import __version__, util
from app.models import (
    Assignment,
    Edit,
    Event,
    Grant,
    KindEvent,
    KindObject,
)
from tests.dummy import DummyProvider

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

    @pytest
    def test_document_deletion(self, dummy: DummyProvider):
        documents, session = dummy.get_documents(15), dummy.session
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

            q_assignment_uuids = document.q_select_assignment(
                exclude_deleted=False,
            )
            q_assignment_uuids = select(uuid_column).select_from(
                q_assignment_uuids.subquery()
            )

            uuid_assignment = set(session.scalars(q_assignment_uuids))
            if not uuid_assignment:
                n_empty_assignments += 1

            # NOTE: Because there are not dummies.
            q_edit_uuids = select(Edit.uuid).where(Edit.id_document == document.id)
            uuid_edit = set(session.scalars(q_edit_uuids))

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

            q_edit_remaining = select(func.count(Edit.uuid)).where(
                Edit.uuid.in_(uuid_edit)
            )
            if p := session.scalar(q_edit_remaining):
                msg = msg_fmt.format(p, len(uuid_edit), "edits")
