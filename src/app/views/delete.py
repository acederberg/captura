from http import HTTPMethod
from typing import Any, Callable, Dict, List, Set, Tuple, Type, overload

from app import __version__, util
from app.auth import Token
from app.depends import DependsToken
from app.models import (Assignment, AssocCollectionDocument,
                        ChildrenAssignment, Collection, Document, Edit, Event,
                        Grant, KindEvent, KindObject, Resolvable,
                        ResolvableMultiple, ResolvableSingular, Singular, User)
from app.schemas import EventSchema
from app.views.access import Access, WithAccess, with_access
from app.views.base import (Data, DataResolvedAssignment, DataResolvedGrant,
                            KindData, ResolvedAssignmentCollection,
                            ResolvedAssignmentDocument, ResolvedCollection,
                            ResolvedDocument, ResolvedEdit,
                            ResolvedGrantDocument, ResolvedGrantUser,
                            ResolvedUser)
from pydantic import BaseModel
from sqlalchemy import Delete as sqaDelete
from sqlalchemy import (Select, Update, delete, false, literal_column, select,
                        true, union, update)
from sqlalchemy.orm import Session


class AssocData(BaseModel):
    uuid_target_active: Set[str]
    uuid_target_deleted: Set[str]

    uuid_assoc_active: Set[str]
    uuid_assoc_deleted: Set[str]


class Delete(WithAccess):
    """Perform deletions."""

    # ----------------------------------------------------------------------- #
    # Helpers for force deletion/PUT
    # Looks nasty, but prevents having to maintain four instances of the same
    # code.

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

        :returns: The active target uuids with active assignments or grants.
        """
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
                assoc_data, uuid_assoc_rm, q_del = self._try_force(
                    T_assoc := Grant, source, uuid_target, force=force
                )
            case ResolvedAssignmentDocument(
                document=source,
                uuid_collections=uuid_target,
            ) | ResolvedAssignmentCollection(
                collection=source,
                uuid_documents=uuid_target,
            ):
                assoc_data, uuid_assoc_rm, q_del = self._try_force(
                    T_assoc := Assignment, source, uuid_target, force=force
                )
            case bad:
                msg = f"Invalid data of kind `{data.kind}` if `{bad}`."
                raise ValueError(msg)

        q_assocs = T_assoc.q_uuid(uuid_assoc_rm)
        assocs = tuple(self.session.execute(q_assocs).scalars())
        return assoc_data, assocs, q_del, T_assoc

    # FINALLY!
    @overload
    def assoc(
        self,
        data: Data[ResolvedGrantUser],
        force: bool | None = None,
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
    ) -> Tuple[
        DataResolvedAssignment | DataResolvedGrant,
        AssocData,
        Update[Assignment] | sqaDelete[Grant],
        Type[Assignment] | Type[Grant],
    ]:
        session = self.session
        assoc_data, assocs, q_del, T_assoc = self.try_force(data, force=force)

        data.event = self.assoc_event(data, assocs)
        session.add(data.event)
        session.execute(q_del)
        session.commit()
        session.refresh(data.event)

        return data, assoc_data, q_del, T_assoc

    @property
    def event_common(self) -> Dict[str, Any]:
        return dict(**super().event_common, kind=KindEvent.delete)

    def assoc_event(self, data: DataResolvedGrant | DataResolvedAssignment, assocs: Tuple[Grant, ...] | Tuple[Assignment, ...],) -> Event:

        # NOTE: Base event indicates the document, secondary event
        #       indicates the users for which permissions were revoked.
        #       Tertiary event indicates information about the association
        #       object. The shape of the tree is based off of the shape of
        #       the url on which this function can be called, where the
        #       document is first, the users are second, and the grants
        #       exist only as JSON.
        event_common = self.event_common
        target_attr_name = data.data.kind_target.name
        uuid_target_attr_name = f"uuid_{target_attr_name}"

        return Event(
            **event_common,
            uuid_obj=data.data.uuid_source,
            kind_obj=data.data.kind_source,
            children=[
                Event(
                    **event_common,
                    kind_obj=data.data.kind_target,
                    uuid_obj=getattr(assoc, uuid_target_attr_name),
                    children=[
                        Event(
                            **event_common,
                            kind_obj=data.data.kind_assoc,
                            uuid_obj=assoc.uuid,
                        )
                    ],
                )
                for assoc in assocs
            ],
        )

    # ----------------------------------------------------------------------- #

    def user(self, data: Data[ResolvedUser]) -> Data[ResolvedUser]:
        ...

    def collection(
        self,
        data: Data[ResolvedCollection],
    ) -> Data[ResolvedCollection]:
        ...

    #     session = self.session
    #     collection = Collection.resolve(session, resolve_collection)
    #     user = User.resolve(session, resolve_user or self.token.uuid)
    #
    #     # Find docs
    #     p = select(Document.uuid).join(AssocCollectionDocument)
    #     p = p.where(AssocCollectionDocument.id_collection == collection.id)
    #     q = select(literal_column("uuid"))
    #     q = union(q.select_from(collection.q_select_documents()), p)
    #     uuid_document = set(session.execute(q).scalars())
    #
    #     # Delete assigns and get events before deletion.
    #     event_assign = self.assignment_collection(
    #         collection,
    #         uuid_document,
    #         resolve_user=user,
    #     )
    #
    #     if self.force:
    #         session.delete(collection)
    #     else:
    #         collection.deleted = True
    #         session.add(collection)
    #
    #     # Create event
    #     session.add(
    #         event := Event(
    #             **self.event_common,
    #             uuid_obj=collection.uuid,
    #             children=[event_assign],
    #             # detail=detail,
    #         )
    #     )
    #     session.commit()
    #     session.refresh(event)
    #     return event
    #

    # NOTE:
    def document(
        self,
        data: Data[ResolvedDocument],
    ) -> Data[ResolvedDocument]:
        ...

    def edit(self, data: Data[ResolvedEdit]) -> Data[ResolvedEdit]:
        ...

    # ----------------------------------------------------------------------- #

    def assignment_collection(
        self,
        data: Data[ResolvedAssignmentCollection],
    ) -> Data[ResolvedAssignmentCollection]:
        data, *_ = self.assoc(data)
        return data

    def assignment_document(
        self, data: Data[ResolvedAssignmentDocument]
    ) -> Data[ResolvedAssignmentDocument]:
        data, *_ = self.assoc(data)
        return data

    a_assignment_document = with_access(Access.assignment_document)(assignment_document)
    a_assignment_collection = with_access(Access.assignment_collection)(
        assignment_collection
    )

    # ----------------------------------------------------------------------- #
    # Grants

    def grant_user(
        self,
        data: Data[ResolvedGrantUser],
    ) -> Data[ResolvedGrantUser]:
        data, *_ = self.assoc(data)
        return data

    def grant_document(
        self, data: Data[ResolvedGrantDocument]
    ) -> Data[ResolvedGrantDocument]:
        data, *_ = self.assoc(data)
        return data

    a_grant_document = with_access(Access.grant_document)(grant_user)
    a_grant_user = with_access(Access.grant_user)(grant_document)



class WithDelete(WithAccess):
    delete: Delete

    def __init__(
        self,
        session: Session,
        token: Token | Dict[str, Any] | None,
        method: HTTPMethod | str,
        *,
        detail: str,
        api_origin: str,
        force: bool = False,
        access: Access | None = None,
        delete: Delete | None = None,
    ):
        super().__init__(
            session,
            token,
            method,
            detail=detail,
            api_origin=api_origin,
            force=force,
            access=access,
        )

        if delete is None:
            delete = self.then(
                Delete,
                detail=detail,
                api_origin=api_origin,
                force=force,
                access=self.access,
            )
        self.delete = delete
