# =========================================================================== #
import functools
from http import HTTPMethod
from typing import Any, Dict, Generator, List, Set, Tuple, Type, overload

from fastapi import HTTPException
from pydantic import BaseModel, TypeAdapter
from sqlalchemy import Delete as sqaDelete
from sqlalchemy import Select, Update, delete, false, true, update
from sqlalchemy.orm import Session

# --------------------------------------------------------------------------- #
from app import __version__, util
from app.auth import Token
from app.controllers.access import Access, WithAccess, with_access
from app.controllers.base import (
    Data,
    DataResolvedAssignment,
    DataResolvedGrant,
    ResolvedAssignmentCollection,
    ResolvedAssignmentDocument,
    ResolvedCollection,
    ResolvedDocument,
    ResolvedEdit,
    ResolvedEvent,
    ResolvedGrantDocument,
    ResolvedGrantUser,
    ResolvedObjectEvents,
    ResolvedUser,
)
from app.models import (
    Assignment,
    Collection,
    Document,
    Edit,
    Event,
    Grant,
    KindEvent,
    KindObject,
    Level,
    User,
)
from app.schemas import CollectionSchema, mwargs


class AssocData(BaseModel):
    uuid_target_active: Set[str]
    uuid_target_deleted: Set[str]

    uuid_assoc_active: Set[str]
    uuid_assoc_deleted: Set[str]


class Delete(WithAccess):
    """Perform deletions."""

    def _event(self, item: Event, info: Set[Tuple[KindObject, None | str]]) -> int:
        # Pruning events should not create any more events besides one marking
        # that the pruning was performed.

        meth = (
            self.session.delete
            if self.force
            else lambda child: setattr(child, "deleted", True)
        )
        _ = tuple(
            (
                meth(child),
                info.add(
                    (
                        child.kind_obj,
                        child.uuid_obj,
                    )
                ),
            )
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
    ) -> Data[ResolvedEvent]:
        ...

    @overload
    def event(
        self,
        data: Data[ResolvedObjectEvents],
        # commit: bool = False,
    ) -> Data[ResolvedObjectEvents]:
        ...

    def event(
        self,
        data: Data[ResolvedEvent] | Data[ResolvedObjectEvents],
        # commit: bool = False,
    ) -> Data[ResolvedEvent] | Data[ResolvedObjectEvents]:
        obj_info = set()
        n = sum(self._event(item, obj_info) for item in data.data.events)
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
    # Helpers for force deletion/PUT
    # Looks nasty, but prevents having to maintain four instances of the same
    # code.

    @property
    def event_common(self) -> Dict[str, Any]:
        return dict(**super().event_common, kind=KindEvent.delete)

    def split_assocs(
        self,
        T_assoc: Type[Grant] | Type[Assignment],
        source: Any,
        uuid_target: Set[str],
    ) -> AssocData:
        if not len(uuid_target):
            raise ValueError("`uuid_target` must not be empty.")

        q_assoc: Select
        match (KindObject(T_assoc.__tablename__), source):
            case (KindObject.grant, User() as user):
                q_assoc = user.q_select_grants(
                    uuid_target,
                    exclude_deleted=False,
                )
                uuid_target_attr = "uuid_document"
            case (KindObject.grant, Document() as document):
                q_assoc = document.q_select_grants(
                    uuid_target,
                    exclude_deleted=False,
                )
                uuid_target_attr = "uuid_user"
            case (KindObject.assignment, Document() as document):
                q_assoc = document.q_select_assignment(
                    uuid_target,
                    exclude_deleted=False,
                )
                uuid_target_attr = "uuid_collection"
            case (KindObject.assignment, Collection() as collection):
                q_assoc = collection.q_select_assignment(
                    uuid_target,
                    exclude_deleted=False,
                )
                uuid_target_attr = "uuid_document"
            case bad:
                msg = f"Invalid case `{bad}`."
                raise ValueError(msg)

        def one(bool_) -> Tuple[Set[str], Set[str]]:
            """Returns a tuple of a set of uuids of inactive assignments and
            uuids of active targets.
            """
            q = q_assoc.where(T_assoc.deleted == bool_())
            items = tuple(self.session.execute(q).scalars())
            items = tuple(
                (item.uuid, getattr(item, uuid_target_attr)) for item in items
            )
            if not items:
                return (set(), set())
            return tuple(set(item) for item in zip(*items))

        deleted, active = (one(true), one(false))
        return AssocData(
            uuid_assoc_deleted=deleted[0],
            uuid_target_deleted=deleted[1],
            uuid_assoc_active=active[0],
            uuid_target_active=active[1],
        )

    def _try_force(
        self,
        T_assoc: Type[Grant] | Type[Assignment],
        source: Any,
        uuid_target: Set[str],
        force: bool | None = None,
    ) -> Tuple[AssocData, Set[str], sqaDelete | Update]:
        """Helper for `try_force`. Find active target uuids and build the query
        to (hard/soft) delete.

        :raises ValueError: When `uuid_target` is empty because no query can
            be generated.
        :returns: The active target uuids with active assignments or grants.
        """
        if not len(uuid_target):
            raise ValueError("`uuid_target` must not be empty.")

        assoc_data = self.split_assocs(T_assoc, source, uuid_target)
        uuid_assoc_rm = assoc_data.uuid_assoc_active.copy()

        force = self.force if force is None else force
        if force:
            uuid_assoc_rm |= assoc_data.uuid_assoc_deleted
            q_del = delete(T_assoc).where(T_assoc.uuid.in_(uuid_assoc_rm))
        else:
            q_del = (
                update(T_assoc)
                .where(T_assoc.uuid.in_(uuid_assoc_rm))
                .values(deleted=True)
            )
        return assoc_data, uuid_assoc_rm, q_del

    @overload
    def try_force(
        self,
        data: DataResolvedGrant,
        force: bool | None = None,
    ) -> Tuple[
        AssocData,
        Tuple[Grant, ...],
        Update[Grant] | sqaDelete[Grant],
        Type[Grant] | Type[Assignment],
    ]:
        ...

    @overload
    def try_force(
        self,
        data: DataResolvedAssignment,
        force: bool | None = None,
    ) -> Tuple[
        AssocData,
        Tuple[Assignment, ...],
        Update[Assignment] | sqaDelete[Assignment],
        Type[Grant] | Type[Assignment],
    ]:
        ...

    def try_force(
        self,
        data: Data,
        force: bool | None = None,
    ) -> Tuple[
        AssocData,
        Tuple[Assignment, ...] | Tuple[Grant, ...],
        sqaDelete | Update,
        Type[Grant] | Type[Assignment],
    ]:
        uuid_target: Set[str]
        match data.data:
            case ResolvedGrantUser(
                user=source,
                uuid_documents=uuid_target,
            ) | ResolvedGrantDocument(
                document=source,
                uuid_users=uuid_target,
            ):
                T_assoc = Grant
                # assoc_data, uuid_assoc_rm, q_del = self._try_force(
                #     T_assoc := Grant, source, uuid_target, force=force
                # )
            case ResolvedAssignmentDocument(
                document=source,
                uuid_collections=uuid_target,
            ) | ResolvedAssignmentCollection(
                collection=source,
                uuid_documents=uuid_target,
            ):
                T_assoc = Assignment
                # assoc_data, uuid_assoc_rm, q_del = self._try_force(
                #     T_assoc := Assignment, source, uuid_target, force=force
                # )
            case bad:
                msg = f"Invalid data of kind `{data.kind}` if `{bad}`."
                raise ValueError(msg)

        assoc_data, uuid_assoc_rm, q_del = self._try_force(
            T_assoc, source, uuid_target, force=force
        )
        q_assocs = T_assoc.q_uuid(uuid_assoc_rm)
        assocs = tuple(self.session.execute(q_assocs).scalars())
        return assoc_data, assocs, q_del, T_assoc

    @overload
    def assoc(
        self,
        data: Data[ResolvedGrantUser],
        force: bool | None = None,
        # commit: bool = False,
    ) -> Tuple[
        Data[ResolvedGrantUser],
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Assignment],
    ]:
        ...

    @overload
    def assoc(
        self,
        data: Data[ResolvedGrantDocument],
        force: bool | None = None,
        # commit: bool = False,
    ) -> Tuple[
        Data[ResolvedGrantDocument],
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Assignment],
    ]:
        ...

    @overload
    def assoc(
        self,
        data: Data[ResolvedAssignmentDocument],
        force: bool | None = None,
        # commit: bool = False,
    ) -> Tuple[
        Data[ResolvedAssignmentDocument],
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Assignment],
    ]:
        ...

    @overload
    def assoc(
        self,
        data: Data[ResolvedAssignmentCollection],
        force: bool | None = None,
        # commit: bool = False,
    ) -> Tuple[
        Data[ResolvedAssignmentCollection],
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Assignment],
    ]:
        ...

    def assoc(
        self,
        data: DataResolvedAssignment | DataResolvedGrant,
        force: bool | None = None,
        # commit: bool = False,
    ) -> Tuple[
        DataResolvedAssignment | DataResolvedGrant,
        AssocData,
        Update[Assignment] | sqaDelete[Grant],
        Type[Assignment] | Type[Grant],
    ]:
        assoc_data, assocs, q_del, T_assoc = self.try_force(data, force=force)
        self.session.execute(q_del)
        data.data.delete = self.force
        data.event = self.create_event_assoc(data, assocs)

        return data, assoc_data, q_del, T_assoc

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
        # commit: bool = False,
    ) -> Data[ResolvedAssignmentCollection]:
        data, *_ = self.assoc(data)  # , commit=commit)
        return data

    def assignment_document(
        self, data: Data[ResolvedAssignmentDocument]  # , commit: bool = False
    ) -> Data[ResolvedAssignmentDocument]:
        data, *_ = self.assoc(data)  # , commit=commit)
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
        self, data: Data[ResolvedGrantUser]  # , commit: bool = False
    ) -> Data[ResolvedGrantUser]:
        data, *_ = self.assoc(data)  # , commit=commit)
        return data

    def grant_document(
        self, data: Data[ResolvedGrantDocument]  # , commit: bool = False
    ) -> Data[ResolvedGrantDocument]:
        data, *_ = self.assoc(data)  # , commit=commit)
        return data

    a_grant_document = with_access(Access.d_grant_document)(grant_document)
    a_grant_user = with_access(Access.d_grant_user)(grant_user)

    # ----------------------------------------------------------------------- #

    def _user(
        self, data: Data[ResolvedUser], user: User  # , commit: bool = False
    ) -> Data[ResolvedUser]:
        session = self.session

        # Cleanup documents that only this user owns.
        documents_exclusive: Tuple[Document, ...] = tuple(
            session.execute(user.q_select_documents_exclusive()).scalars()
        )
        data_documents = mwargs(
            Data[ResolvedDocument],
            token_user=self.token_user,
            data=ResolvedDocument.model_construct(
                documents=documents_exclusive,
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
        documents = set(self.session.execute(q).scalars())
        # q_assignments = collection.q_select_assignment()
        # assignments = set(self.)

        # Delete assigns and get events before deletion.
        data_assignments = mwargs(
            Data,
            token_user=data.token_user,
            data=mwargs(
                ResolvedAssignmentCollection,
                collection=collection,
                documents=documents,
                assignments=None,
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
        if not len(collections):
            return data

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
        if collections := tuple(session.execute(q_collections).scalars()):
            data_assignment = mwargs(
                Data[ResolvedAssignmentDocument],
                token_user=self.token_user,
                data=mwargs(
                    ResolvedAssignmentDocument,
                    document=document,
                    collections=collections,
                    assignments=None,
                ),
            )
            self.assignment_document(data_assignment)
            data.add(data_assignment)

        edits = document.edits
        if edits:
            data_edit = mwargs(
                Data[ResolvedEdit],
                token_user=self.token_user,
                data=mwargs(
                    ResolvedEdit,
                    edits=edits,
                    token_user_grants=data.data.token_user_grants,
                    grants=data.data.token_user_grants,
                ),
            )
            self.edit(data_edit)
            data.add(data_edit)

    def document(
        self,
        data: Data[ResolvedDocument],
        # commit: bool = False,
    ) -> Data[ResolvedDocument]:
        documents = data.data.documents
        if not len(documents):
            return data

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

    # ----------------------------------------------------------------------- #

    def _edit(
        self,
        data: Data[ResolvedEdit],
        edit: Edit,  # *, commit: bool = False
    ) -> None:
        session = self.session

        def rm() -> None:
            # NOTE: Hard deletion handled in `data.commit()`
            if not self.force:
                edit.deleted = True
                session.add(edit)

            event = Event(
                **self.event_common,
                kind_obj=KindObject.edit,
                uuid_obj=edit.uuid,
            )
            if data.event is not None:
                data.event.children.append(event)
            else:
                data.event = event

            # data.commit(session, commit)

        user_token = data.token_user or self.token_user
        user_token_grant = data.data.token_user_grants[user_token.uuid]

        user_edit = edit.user
        if user_edit == user_token:
            return rm()

        q_user_edit_grant = user_edit.q_select_grants({edit.document.uuid})
        user_edit_grant = self.session.execute(q_user_edit_grant).scalar()

        # Depends on current grant of user_edit_grant so that, for instance,
        # a malicious editor can be rejected from the group and their edits may
        # be undone.
        detail = dict(
            uuid_user_token=user_token.uuid,
            uuid_user_edit=user_edit.uuid,
        )
        match (user_token_grant.level, user_edit_grant):
            case (Level.own, None):
                return rm()
            case (Level.own, Grant(level=user_edit_level)):
                if user_edit_level == Level.own:
                    detail.update(msg="Cannot delete edit of other owner.")
                    raise HTTPException(403, detail=detail)
                return rm()
            case (user_token_level, None | Grant()):
                detail.update(
                    msg="Cannot delete edit of other user when not an owner",
                    level=user_token_level.name,
                )
                raise HTTPException(403, detail=dict())
            case _:
                raise ValueError()

    def edit(
        self,
        data: Data[ResolvedEdit],  # commit: bool = False
    ) -> Data[ResolvedEdit]:
        edits = data.data.edits

        # NOTE: Only owners can delete the edits of other contributors.
        data.event = Event(
            kind_obj=KindObject.bulk,
            uuid_obj=None,
            **self.event_common,
        )
        tuple(self._edit(data, edit) for edit in edits)
        # data.commit(self.session, commit)

        return data

    a_edit = with_access(Access.d_edit)(edit)


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
