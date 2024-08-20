# =========================================================================== #
from http import HTTPMethod
from typing import Any, Dict, Self, Set, Tuple, Type, overload

from pydantic import BaseModel, model_validator
from rich.table import Table
from sqlalchemy import Delete as sqaDelete
from sqlalchemy import Update, and_, delete, false, or_, select, true, update
from sqlalchemy.orm import Session

# --------------------------------------------------------------------------- #
from captura import util
from captura.auth import Token
from captura.controllers.access import Access, WithAccess, with_access
from captura.controllers.base import (
    Data,
    DataResolvedAssignment,
    DataResolvedGrant,
    ResolvedAssignmentCollection,
    ResolvedAssignmentDocument,
    ResolvedCollection,
    ResolvedDocument,
    ResolvedEvent,
    ResolvedGrantDocument,
    ResolvedGrantUser,
    ResolvedObjectEvents,
    ResolvedUser,
)
from captura.models import (
    Assignment,
    Collection,
    Document,
    Event,
    Grant,
    KindEvent,
    KindObject,
    User,
    uuids,
)
from captura.schemas import mwargs

logger = util.get_logger(__name__)


class AssocData(BaseModel):
    uuid_target_none: Set[str]
    uuid_assoc_none: Set[str]

    uuid_target_active: Set[str]
    uuid_target_deleted: Set[str]

    uuid_assoc_active: Set[str]
    uuid_assoc_deleted: Set[str]

    @model_validator(mode="after")
    def validate_no_intersections(self) -> Self:
        assert not len(self.uuid_target_active & self.uuid_target_deleted)
        assert not len(self.uuid_target_active & self.uuid_target_none)
        assert not len(self.uuid_target_deleted & self.uuid_target_none)

        assert not len(self.uuid_assoc_active & self.uuid_assoc_deleted)
        assert not len(self.uuid_assoc_active & self.uuid_assoc_none)
        assert not len(self.uuid_assoc_deleted & self.uuid_assoc_none)

        assert len(self.uuid_target_active) == len(self.uuid_assoc_active)
        assert len(self.uuid_target_deleted) == len(self.uuid_assoc_deleted)

        return self

    def render(self) -> Table:
        table = Table(show_header=False, show_lines=False, pad_edge=False)
        table.add_column()
        table.add_column()
        table.add_row(
            "uuid_target_none",
            str(self.uuid_target_none),
            style="red",
        )
        table.add_row(
            "uuid_target_active",
            str(self.uuid_target_active),
            style="blue",
        )
        table.add_row(
            "uuid_target_deleted",
            str(self.uuid_target_deleted),
            style="green",
        )
        table.add_row(
            "uuid_assoc_none",
            str(self.uuid_assoc_none),
            style="red",
        )
        table.add_row(
            "uuid_assoc_active",
            str(self.uuid_assoc_active),
            style="blue",
        )
        table.add_row(
            "uuid_assoc_deleted",
            str(self.uuid_assoc_deleted),
            style="green",
        )
        return table

    def q_del(self, model_assoc: Type, force: bool, *, rm_active: bool = True):
        uuid_assoc_rm = self.uuid_assoc_active.copy() if rm_active else set()

        q_del: Update | sqaDelete
        if force:
            uuid_assoc_rm |= self.uuid_assoc_deleted
            q_del = delete(model_assoc).where(model_assoc.uuid.in_(uuid_assoc_rm))
        else:
            q_del = (
                update(model_assoc)
                .where(model_assoc.uuid.in_(uuid_assoc_rm))
                .values(deleted=True)
            )

        return q_del, uuid_assoc_rm


class Delete(WithAccess):
    """Perform deletions."""

    @property
    def event_common(self) -> Dict[str, Any]:
        return dict(**super().event_common, kind=KindEvent.delete)

    def _event(self, item: Event, info: Set[Tuple[KindObject, None | str]]) -> int:
        # Pruning events should not create any more events besides one marking
        # that the pruning was performed.

        meth = (
            self.session.delete
            if self.force
            else lambda child: setattr(child, "deleted", True)
        )
        _ = tuple(
            (meth(child), info.add((child.kind_obj, child.uuid_obj)))  # type: ignore[func-returns-value]
            for child in item.flattened()
        )

        return len(_)

    def event_event(
        self,
        data: Data[ResolvedEvent] | Data[ResolvedObjectEvents],
        n: int,
        info: Set[Tuple[KindObject, str]],
    ) -> Event:
        token_user = data.token_user or self.token_user
        event = Event(
            **self.event_common,
            kind_obj=KindObject.user,
            uuid_obj=token_user.uuid,
            detail=f"User pruned `{n}` events.",
        )

        specs: Tuple[Tuple[KindObject, str | None], ...]
        match data.data:
            case ResolvedEvent(events=events):
                specs = tuple((ee.kind_obj, ee.uuid_obj) for ee in events)
            case ResolvedObjectEvents(kind_obj=kind_obj, uuid_obj=uuid_obj):
                specs = ((kind_obj, uuid_obj),)
            case _:
                raise ValueError(f"Invalid data of kind `{data.kind}`.")

        ff = "Events pruned by pruning object of kind `{0}` with uuid `{1}`."
        event.children = [
            Event(
                **self.event_common,
                kind_obj=kind_obj,
                uuid_obj=uuid_obj,
                detail=(detail := ff.format(kind_obj, uuid_obj)),
                # Every object should have a record.
                children=[
                    Event(
                        **self.event_common,
                        kind_obj=collatoral_kind_obj,
                        uuid_obj=collatoral_uuid_obj,
                        detail=detail,
                    )
                    for collatoral_kind_obj, collatoral_uuid_obj in info
                ],
            )
            for kind_obj, uuid_obj in specs
        ]
        return event

    @overload
    def event(
        self,
        data: Data[ResolvedEvent],
        # commit: bool = False,
    ) -> Data[ResolvedEvent]: ...

    @overload
    def event(
        self,
        data: Data[ResolvedObjectEvents],
        # commit: bool = False,
    ) -> Data[ResolvedObjectEvents]: ...

    def event(
        self,
        data: Data[ResolvedEvent] | Data[ResolvedObjectEvents],
        # commit: bool = False,
    ) -> Data[ResolvedEvent] | Data[ResolvedObjectEvents]:
        obj_info = set()  # type: ignore[var-annotated]
        n = sum(self._event(item, obj_info) for item in data.data.events)  # type: ignore[misc]
        data.event = self.event_event(data, n, obj_info)
        data.data.delete = True
        return data

    def object_events(
        self,
        data: Data[ResolvedObjectEvents],
    ) -> Data[ResolvedObjectEvents]:
        _ = self.event(data)
        return data

    a_object_events = with_access(Access.d_object_events)(object_events)

    # ----------------------------------------------------------------------- #
    # NOTE: Assocs crap

    def split_assocs(
        self,
        data: DataResolvedGrant | DataResolvedAssignment,
    ) -> Tuple[AssocData, Type]:
        model_assoc = data.data.get_model("assoc")
        model_target = data.data.get_model("target")
        q_assoc = (
            select(model_assoc)
            .join(model_target)
            .where(
                or_(
                    model_assoc.uuid.in_(data.data.uuid_assoc),
                    and_(
                        model_target.uuid.in_(data.data.uuid_target),
                        getattr(model_assoc, "id_" + data.data.kind_source.name)
                        == data.data.source.id,
                    ),
                )
            )
        )
        uuid_target_attr = "uuid_" + data.data.kind_target.name

        # NOTE: Simplify this.
        def one(bool_) -> Tuple[Set[str], Set[str]]:
            """Returns a tuple of a set of uuids of inactive assignments and
            uuids of active targets.
            """
            q = q_assoc.where(model_assoc.deleted == bool_())
            items = tuple(self.session.scalars(q))
            items = tuple(
                (item.uuid, getattr(item, uuid_target_attr)) for item in items
            )
            if not items:
                return (set(), set())
            return tuple(set(item) for item in zip(*items))  # type: ignore[return-value]

        deleted, active = (one(true), one(false))
        return (
            AssocData(
                uuid_assoc_none=data.data.uuid_assoc - deleted[0] - active[0],
                uuid_target_none=data.data.uuid_target - deleted[1] - active[1],
                uuid_assoc_deleted=deleted[0],
                uuid_target_deleted=deleted[1],
                uuid_assoc_active=active[0],
                uuid_target_active=active[1],
            ),
            model_assoc,
        )

    def assoc(
        self,
        data: DataResolvedAssignment | DataResolvedGrant,
    ) -> AssocData:
        assoc_data, model_assoc = self.split_assocs(data)
        q_del, uuid_assoc_rm = assoc_data.q_del(model_assoc, self.force)

        q_assocs = model_assoc.q_uuid(uuid_assoc_rm)
        assocs = tuple(self.session.scalars(q_assocs))

        self.session.execute(q_del)
        data.data.delete = self.force
        data.event = self.create_event_assoc(data, assocs)

        return assoc_data

    def create_event_assoc(
        self,
        data: DataResolvedGrant | DataResolvedAssignment,
        assocs: Tuple[Grant, ...] | Tuple[Assignment, ...],
    ) -> Event:
        # NOTE: Base event indicates the document, secondary event
        #       indicates the users for which permissions were revoked.
        #       Tertiary event indicates information about the association
        #       object. The shape of the tree is based off of the shape of
        #       the url on which this function can be called, where the
        #       document is first, the users are second, and the grants
        #       exist only as JSON.
        event_common = self.event_common
        kind_target = data.data.kind_target
        kind_assoc, kind_source = data.data.kind_assoc, data.data.kind_source

        uuid_target_attr_name = f"uuid_{kind_target.name}"
        detail = f"`{kind_assoc.name}`s deleted via `{kind_source.name}`."

        return Event(
            **event_common,
            uuid_obj=data.data.uuid_source,
            kind_obj=kind_source,
            detail=detail,
            children=[
                Event(
                    **event_common,
                    kind_obj=kind_target,
                    uuid_obj=getattr(assoc, uuid_target_attr_name),
                    detail=detail,
                    children=[
                        Event(
                            **event_common,
                            kind_obj=kind_assoc,
                            uuid_obj=assoc.uuid,
                            detail=detail,
                        )
                    ],
                )
                for assoc in assocs
            ],
        )

    # ----------------------------------------------------------------------- #

    def assignment_collection(
        self,
        data: Data[ResolvedAssignmentCollection],
    ) -> Data[ResolvedAssignmentCollection]:
        self.assoc(data)
        return data

    def assignment_document(
        self, data: Data[ResolvedAssignmentDocument]
    ) -> Data[ResolvedAssignmentDocument]:
        self.assoc(data)
        return data

    a_assignment_document = with_access(Access.d_assignment_document)(
        assignment_document
    )
    a_assignment_collection = with_access(Access.d_assignment_collection)(
        assignment_collection
    )

    # ----------------------------------------------------------------------- #
    # Grants

    def grant_user(
        self,
        data: Data[ResolvedGrantUser],
    ) -> Data[ResolvedGrantUser]:
        self.assoc(data)
        return data

    def grant_document(
        self, data: Data[ResolvedGrantDocument]
    ) -> Data[ResolvedGrantDocument]:
        self.assoc(data)
        return data

    a_grant_document = with_access(Access.d_grant_document)(grant_document)
    a_grant_user = with_access(Access.d_grant_user)(grant_user)

    # ----------------------------------------------------------------------- #

    def _user(
        self,
        data: Data[ResolvedUser],
        user: User,  # , commit: bool = False
    ) -> Data[ResolvedUser]:
        logger.debug("Deleting user `%s`.", user.uuid)
        session = self.session

        # Cleanup documents that only this user owns.
        documents_exclusive: Tuple[Document, ...] = tuple(
            session.execute(user.q_select_documents_exclusive()).scalars()
        )
        data_documents = mwargs(
            Data[ResolvedDocument],
            token_user=self.token_user,
            data=mwargs(
                ResolvedDocument,
                documents=documents_exclusive,
                token_user_grants=dict(),
            ),
        )
        self.document(data_documents)
        data.add(data_documents)

        # Cleanup collections.
        q_collections = user.q_collections(exclude_deleted=False)

        collections: Tuple[Collection, ...]
        collections = tuple(self.session.execute(q_collections).scalars())
        data_collections = mwargs(
            Data[ResolvedCollection],
            token_user=self.token_user,
            data=mwargs(
                ResolvedCollection,
                collections=collections,
            ),
        )
        self.collection(data_collections)
        data.add(data_collections)

        # NOTE: Should be done by `data.commit`.

        # if self.force:
        #     session.delete(User)
        # else:
        #     user.deleted = True
        #     session.add(user)

        # Event
        data.event = Event(
            **self.event_common,
            kind_obj=KindObject.user,
            uuid_obj=user.uuid,
            children=[
                ee
                for data_item in (data_documents, data_collections)
                if (ee := data_item.event) is not None
            ],
        )
        # data.data.commit(session, commit, delete=self.force)

        return data

    def user(
        self,
        data: Data[ResolvedUser],  # commit: bool = False
    ) -> Data[ResolvedUser]:
        users = data.data.users

        data_users = tuple(self._user(data, user) for user in users)
        data.event = Event(
            **self.event_common,
            kind_obj=KindObject.bulk,
            uuid_obj=None,
            children=[dd.event for dd in data_users],
        )
        data.add(*data_users)
        # data.data.commit(self.session, commit)

        return data

    a_user = with_access(Access.d_user)(user)

    # ----------------------------------------------------------------------- #

    def _collection(
        self,
        data: Data[ResolvedCollection],
        collection: Collection,
        # commit: bool = False,
    ) -> Data[ResolvedAssignmentCollection]:
        q = collection.q_select_documents(exclude_deleted=not self.force)
        documents = tuple(self.session.execute(q).scalars())
        q_assignments = (
            select(Assignment)
            .join(Document)
            .where(
                Document.uuid.in_(uuids(documents)),  # type: ignore[type-var]
                Assignment.id_collection == collection.id,
            )
        )
        assignments = {
            aa.uuid_document: aa for aa in self.session.scalars(q_assignments)
        }

        # Delete assigns and get events before deletion.
        data_assignments = mwargs(
            Data,
            token_user=data.token_user,
            data=mwargs(
                ResolvedAssignmentCollection,
                collection=collection,
                documents=documents,
                assignments=assignments,
            ),
        )
        if len(documents):
            _ = self.assignment_collection(data_assignments)

        data.add(data_assignments)

        # NOTE: Hard deletion is best done this way due to session.deleted
        #       strageness.
        if not self.force:
            collection.deleted = True
        else:
            data.data.delete = True
            self.session.delete(collection)

        # Create event
        event_assignments = data_assignments.event
        data_assignments.event = Event(
            **self.event_common,
            kind_obj=KindObject.assignment,
            uuid_obj=collection.uuid,
            detail="Bulk deletion of `assignment`s.",
        )
        if event_assignments is not None:
            data_assignments.event.children.append(event_assignments)

        # data.data.commit(self.session, commit)
        return data_assignments

    def collection(
        self,
        data: Data[ResolvedCollection],
        # commit: bool = False,
    ) -> Data[ResolvedCollection]:
        collections = data.data.collections
        if not (n := len(collections)):
            return data

        logger.debug("Deleting `%s` collections.", n)
        data_assignments = tuple(
            self._collection(data, collection) for collection in collections
        )
        data.event = Event(
            **self.event_common,
            kind_obj=KindObject.collection,
            uuid_obj=None,
            children=[dd.event for dd in data_assignments],
            detail="Bulk deletion of `collection`s.",
        )

        # data.commit(self.session, commit)
        return data

    a_collection = with_access(Access.collection)(collection)

    # ----------------------------------------------------------------------- #

    def _document(
        self,
        data: Data[ResolvedDocument],
        document: Document,
        # *,
        # commit: bool = False,
    ) -> None:
        # Delete grants
        session = self.session
        if not self.force:
            document.deleted = True
        else:
            data.data.delete = True
            self.session.delete(document)

        q_users = document.q_select_users(
            exclude_deleted=not self.force, exclude_pending=False, pending=False
        )
        if users := tuple(session.execute(q_users).scalars()):
            data_grant = mwargs(
                Data[ResolvedGrantDocument],
                token_user=self.token_user,
                data=mwargs(
                    ResolvedGrantDocument,
                    token_user_grants=data.data.token_user_grants,
                    grants=data.data.token_user_grants,
                    document=document,
                    users=users,
                ),
            )
            self.grant_document(data_grant)
            data.add(data_grant)

        q_collections = document.q_select_collections(
            exclude_deleted=not self.force,
        )
        if collections := tuple(session.scalars(q_collections)):
            # NOTE: No deletion, etc. filtering as this is accoplished via
            #       ``q_select_collections``.
            uuid_collections = Collection.resolve_uuid(self.session, collections)
            q_assignments = (
                select(Assignment)
                .join(Collection)
                .where(
                    Assignment.id_document == document.id,
                    Collection.uuid.in_(uuid_collections),
                )
            )
            assignments = {
                aa.uuid_collection: aa for aa in session.scalars(q_assignments)
            }
            data_assignment = mwargs(
                Data[ResolvedAssignmentDocument],
                token_user=self.token_user,
                data=mwargs(
                    ResolvedAssignmentDocument,
                    document=document,
                    collections=collections,
                    assignments=assignments,
                ),
            )
            self.assignment_document(data_assignment)
            data.add(data_assignment)

    def document(
        self,
        data: Data[ResolvedDocument],
        # commit: bool = False,
    ) -> Data[ResolvedDocument]:
        documents = data.data.documents
        if not (n := len(documents)):
            return data

        logger.debug("Deleting `%s` collections", n)
        for document in data.data.documents:
            self._document(data, document)

        data.event = Event(
            **self.event_common,
            kind_obj=KindObject.bulk,
            children=[data_child.event for data_child in data.children],
        )
        data.data.delete = True
        return data

    a_document = with_access(Access.d_document)(document)


class WithDelete(WithAccess):
    delete: Delete

    def __init__(
        self,
        session: Session,
        token: Token | Dict[str, Any] | None,
        method: HTTPMethod | str,
        *,
        api_origin: str,
        force: bool = False,
        access: Access | None = None,
        delete: Delete | None = None,
    ):
        super().__init__(
            session,
            token,
            method,
            api_origin=api_origin,
            force=force,
            access=access,
        )

        if delete is None:
            delete = self.then(
                Delete,
                api_origin=api_origin,
                force=force,
                access=self.access,
            )
        self.delete = delete
