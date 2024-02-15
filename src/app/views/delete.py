from http import HTTPMethod
from typing import Any, Callable, Dict, List, Set, Tuple, Type, overload

from app import __version__, util
from app.auth import Token
from app.depends import DependsToken
from app.models import (
    Assignment,
    AssocCollectionDocument,
    ChildrenAssignment,
    Collection,
    Document,
    Edit,
    Event,
    Grant,
    KindEvent,
    KindObject,
    Resolvable,
    ResolvableMultiple,
    ResolvableSingular,
    User,
)
from app.schemas import EventSchema
from app.views.access import Access, WithAccess, with_access
from app.views.base import (
    Data,
    DataResolvedAssignment,
    DataResolvedGrant,
    KindData,
    ResolvedAssignmentCollection,
    ResolvedAssignmentDocument,
    ResolvedCollection,
    ResolvedDocument,
    ResolvedEdit,
    ResolvedGrantDocument,
    ResolvedGrantUser,
    ResolvedUser,
)
from pydantic import BaseModel
from sqlalchemy import Delete as sqaDelete
from sqlalchemy import (
    Select,
    Update,
    delete,
    false,
    literal_column,
    select,
    true,
    union,
    update,
)
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
    def split_assocs(
        self,
        T_assoc: Type[Grant] | Type[Assignment],
        source: Any,
        uuid_target: Set[str],
    ) -> AssocData:

        q_assoc: Select
        match (kind_obj := KindObject(T_assoc.__tablename__), source):
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
            """returns

            1. Uuids of (in)active assignments.
            2. Uuids of (in)active targets.
            """
            q = q_assoc.where(T_assoc.deleted == bool_())
            print("==========================================================")
            print()
            util.sql(self.session, q)
            print()
            items = tuple(self.session.execute(q).scalars())
            print("----------------------------------------------------------")
            print()
            print("items", items)
            print()
            items = tuple(
                (item.uuid, getattr(item, uuid_target_attr)) for item in items
            )
            print("----------------------------------------------------------")
            print()
            print("items", items)
            print("not items", not items)
            print()
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
    ) -> Tuple[Set[str], sqaDelete | Update]:
        """Helper for `try_force`. Find active target uuids and build the query
        to (hard/soft) delete.

        :returns: The active target uuids with active assignments or grants.
        """
        # uuid_assoc_deleted, uuid_assoc_active = T_assoc.split(
        #     session,
        #     source,
        #     uuid_target,
        # )
        # _, uuid_target_active = T_assoc.split(
        #     session,
        #     source,
        #     uuid_target,
        #     select_parent_uuids=True,
        # )
        res = self.split_assocs(T_assoc, source, uuid_target)
        (
            (uuid_assoc_deleted, uuid_assoc_active),
            (uuid_target_deleted, uuid_target_active),
        ) = res

        if self.force:
            # All assocs should be deleted when force
            uuid_assoc_active |= uuid_assoc_deleted
            q = delete(T_assoc).where(T_assoc.uuid.in_(uuid_assoc_active))
        else:
            q = (
                update(T_assoc)
                .where(T_assoc.uuid.in_(uuid_assoc_active))
                .values(deleted=True)
            )
        return uuid_target_active, q

    def try_force(
        self,
        data: DataResolvedGrant | DataResolvedAssignment,
    ) -> Tuple[Tuple[Assignment, ...] | Tuple[Grant, ...], Update | sqaDelete]:

        uuid_target: Set[str]
        match data.data:
            case ResolvedGrantUser(
                user=source,
                uuid_documents=uuid_target,
            ) | ResolvedGrantDocument(
                document=source,
                uuid_users=uuid_target,
            ):
                uuid_target_active, q_del = self._try_force(
                    Grant, source, uuid_target
                )  # noQA[501]
                q_assocs = source.q_select_grants(
                    uuid_target_active, exclude_deleted=False
                )
            case ResolvedAssignmentCollection(
                collection=source,
                uuid_documents=uuid_target,
            ) | ResolvedAssignmentCollection(
                document=source,
                uuid_collections=uuid_target,
            ):
                uuid_target_active, q_del = self._try_force(
                    Assignment, source, uuid_target
                )
                q_assocs = source.q_select_assignment(
                    uuid_target_active, exclude_deleted=False
                )
            case bad:
                msg = f"Invalid data of kind `{data.kind}` if `{bad}`."
                raise ValueError(msg)

        assocs: Tuple[Assignment, ...] | Tuple[Grant, ...]
        assocs = tuple(self.session.execute(q_assocs).scalars())
        return assocs, q_del

    # ----------------------------------------------------------------------- #

    def user(self, data: Data[ResolvedUser]) -> Data[ResolvedUser]: ...

    def collection(
        self,
        data: Data[ResolvedCollection],
    ) -> Data[ResolvedCollection]: ...

    # NOTE:
    def document(
        self,
        data: Data[ResolvedDocument],
    ) -> Data[ResolvedDocument]: ...

    def edit(self, data: Data[ResolvedEdit]) -> Data[ResolvedEdit]: ...

    # ----------------------------------------------------------------------- #
    # Assignments

    def assignment_try_force(
        self,
        data: DataResolvedAssignment,
    ) -> Tuple[Tuple[Assignment, ...], sqaDelete | Update]:
        """Symetrically generate  deletion query and search for assignments as
        specified by :attr:`force`.

        When `force` is ``True``, all assignments for the source are returned
        and the deletetion statement (locally ``q_del``) will be a hard delete.
        Otherwise, only active assignments are returned and the deletion
        statement will only update the ``delete`` column to be ``False``.

        :returns: The :class:`Assignment`s to be deleted along with the deletion
            statement.
        """

        session = self.session
        source: Document | Collection = data.data.source  # type: ignore[reportGeneralTypeIssues]
        uuid_target: Set[str] = data.data.uuid_target  # type: ignore[reportGeneralTypeIssues]
        uuid_assign_deleted, uuid_assign_active = Assignment.split(
            session, source, uuid_target
        )
        _, uuid_target_active = Assignment.split(
            session, source, uuid_target, select_parent_uuids=True
        )

        # Force == hard delete. Otherwise soft delete.
        if self.force:
            uuid_assign_active |= uuid_assign_deleted
            q_del = delete(AssocCollectionDocument).where(
                AssocCollectionDocument.uuid.in_(uuid_assign_active)
            )
        else:
            q_del = (
                update(AssocCollectionDocument)
                .where(AssocCollectionDocument.uuid.in_(uuid_assign_active))
                .values(deleted=True)
            )

        q_assocs = source.q_select_assignment(uuid_target_active, exclude_deleted=False)
        assocs = tuple(session.execute(q_assocs).scalars())
        return assocs, q_del

    def assignment_collection(
        self,
        data: Data[ResolvedAssignmentCollection],
    ) -> Data[ResolvedAssignmentCollection]:
        session = self.session
        collection = data.data.collection
        assocs, q_del = self.assignment_try_force(data)

        # Create events
        event_common = dict(kind=KindEvent.delete, **self.event_common)
        data.event = Event(
            **event_common,
            kind_obj=KindObject.collection,
            uuid_obj=collection.uuid,
            children=[
                session.refresh(assoc)
                or Event(
                    **event_common,
                    kind_obj=KindObject.document,
                    uuid_obj=assoc.uuid_document,
                    children=[
                        Event(
                            **event_common,
                            kind_obj=KindObject.assignment,
                            uuid_obj=assoc.uuid,
                        )
                    ],
                )
                for assoc in assocs
            ],
        )

        session.execute(q_del)
        session.add(data.event)
        session.commit()
        session.refresh(data.event)

        return data

    def assignment_document(
        self, data: Data[ResolvedAssignmentDocument]
    ) -> Data[ResolvedAssignmentDocument]:
        session = self.session
        document = data.data.document
        assocs, q_del = self.assignment_try_force(data)

        event_common: Dict[str, Any] = self.event_common
        data.event = Event(
            **event_common,
            kind_obj=KindObject.document,
            uuid_obj=document.uuid,
            children=[
                Event(
                    **event_common,
                    kind_obj=KindObject.collection,
                    uuid_obj=assoc.uuid_collection,
                    children=[
                        Event(
                            **event_common,
                            kind_obj=KindObject.assignment,
                            uuid_obj=assoc.uuid,
                        )
                    ],
                )
                for assoc in assocs
            ],
        )
        session.add(data.event)
        session.execute(q_del)
        session.commit()
        session.refresh(data.event)
        return data

    a_access_document = with_access(Access.d_assignment_document)
    a_access_collection = with_access(Access.d_assignment_collection)

    # def collection(
    #     self,
    #     resolve_collection: ResolvableSingular[Collection],
    #     *,
    #     resolve_user: ResolvableSingular[User] | None = None,
    # ) -> Event:
    #
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
    # # ----------------------------------------------------------------------- #
    # # Grants

    def grant_user(
        self,
        data: Data[ResolvedGrantUser],
    ) -> Data[ResolvedGrantUser]: ...

    def grant_document(
        self, data: Data[ResolvedGrantDocument]
    ) -> Data[ResolvedGrantDocument]:

        # NOTE: Since owners cannot reject the ownership of other owners.
        # logger.debug("Verifying revokee permissions.")
        # q_select_grants = document.q_select_grants(uuid_user)
        # uuid_owners: Set[str] = set(
        #     session.execute(
        #         select(literal_column("uuid_user"))
        #         .select_from(q_select_grants)  # type: ignore
        #         .where(literal_column("level") == Level.own)
        #     ).scalars()
        # )
        # if len(uuid_owners):
        #     detail = dict(
        #         msg="Owner cannot reject grants of other owners.",
        #         uuid_user_revoker=uuid_revoker,
        #         uuid_user_revokees=uuid_owners,
        #         uuid_documents=uuid_document,
        #     )
        #     raise HTTPException(403, detail=detail)

        # NOTE: Base event indicates the document, secondary event
        #       indicates the users for which permissions were revoked.
        #       Tertiary event indicates information about the association
        #       object. The shape of the tree is based off of the shape of
        #       the url on which this function can be called, where the
        #       document is first, the users are second, and the grants
        #       exist only as JSON.
        grants = list(session.execute(q_select_grants))
        event_common = dict(
            api_origin="DELETE /grants/documents/<uuid>",
            uuid_user=uuid_revoker,
            kind=KindEvent.grant,
        )
        event = Event(
            **event_common,
            uuid_obj=uuid_document,
            kind_obj=KindObject.document,
            detail="Grants revoked.",
            children=[
                Event(
                    **event_common,
                    kind_obj=KindObject.user,
                    uuid_obj=uuid_user,
                    detail=f"Grant `{grant.level.name}` revoked.",
                    children=[
                        Event(
                            **event_common,
                            kind_obj=KindObject.grant,
                            uuid_obj=grant.uuid,
                            detail=f"Grant `{grant.level.name}` revoked.",
                        )
                    ],
                )
                for grant in grants
            ],
        )
        session.add(event)
        session.execute(
            update(AssocUserDocument)
            .where(document.q_conds_grants(uuid_user))
            .values(deleted=True)
        )
        session.commit()
        session.refresh(event)

        return EventSchema.model_validate(event)  # type: ignore

    # # ----------------------------------------------------------------------- #
    # # Collections
    #
    # def document(
    #     self,
    #     resolvable_document: Resolvable[Document],
    #     *,
    #     token_user: ResolvableSingular[User] | None = None,
    # ) -> Event: ...
    #
    # # ----------------------------------------------------------------------- #
    # # Edits
    # #
    #
    # def edit(
    #     self,
    #     resolvable_edit: Resolvable[Edit],
    #     *,
    #     token_user: ResolvableSingular[User] | None = None,
    # ) -> Event: ...
    #
    # # ----------------------------------------------------------------------- #
    # # Users
    # def user(
    #     self,
    #     resolvable_user: Resolvable[Document],
    #     *,
    #     token_user: ResolvableSingular[User],
    # ) -> Event: ...
    #
    # # ----------------------------------------------------------------------- #


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
        force: bool = True,
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
