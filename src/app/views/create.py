import functools
import json
import secrets
from functools import cached_property
from http import HTTPMethod
from typing import (Any, Callable, Dict, Generic, Protocol, Set, Tuple, Type,
                    TypeVar, Union, overload)

from app import __version__, util
from app.auth import Token
from app.models import (Assignment, Collection, Document, Event, Grant,
                        KindEvent, KindObject, PendingFrom, ResolvableMultiple,
                        ResolvableSingular, ResolvableSourceAssignment,
                        ResolvableTargetAssignment, Tables, User)
from app.schemas import (AssignmentSchema, CollectionCreateSchema,
                         CollectionSchema, CollectionUpdateSchema,
                         DocumentCreateSchema, DocumentUpdateSchema,
                         EditCreateSchema, EventSchema, GrantCreateSchema,
                         PostUserSchema, UserCreateSchema, UserUpdateSchema)
from app.views.access import Access, H, WithAccess, with_access
from app.views.base import (Data, DataResolvedGrant,
                            ResolvedAssignmentCollection,
                            ResolvedAssignmentDocument, ResolvedCollection,
                            ResolvedDocument, ResolvedEdit,
                            ResolvedGrantDocument, ResolvedGrantUser,
                            ResolvedUser)
from app.views.delete import (AssocData, DataResolvedAssignment, Delete,
                              WithDelete)
from fastapi import HTTPException
from sqlalchemy import Delete as sqaDelete
from sqlalchemy import Update, literal_column, select
from sqlalchemy.orm import Session

# --------------------------------------------------------------------------- #
# Typehints for assoc callback.

# NOTE: Typehints bad when `CallableAssocCallback` is protocol, idk why
# NOTE: This also does not work:
#
#       .. code:: python
#
#         CallableAssocCallback = Callable[
#             [
#                 Data[T_AssocCallbackResolved],
#                 T_AssocCallbackTarget,
#             ],
#             T_AssocCallbackAssoc,
#         ]

# NOTE: Fuck this, using lazy callable signature for now.
# T_AssocCallbackResolved = TypeVar(
#     "T_AssocCallbackResolved",
#     ResolvedGrantUser,
#     ResolvedGrantDocument,
#     ResolvedAssignmentDocument,
#     ResolvedAssignmentCollection,
#     covariant=True
# )
# T_AssocCallbackTarget = TypeVar(
#     "T_AssocCallbackTarget", User, Document, Collection
# )
# T_AssocCallbackAssoc = TypeVar(
#     "T_AssocCallbackAssoc", Grant, Assignment
# )
#
#
#
#
# class CallableAssocCallback(
#     Protocol,
#     Generic[
#         T_AssocCallbackTarget,
#         T_AssocCallbackAssoc,
#         T_AssocCallbackResolved,
#     ],
# ):
#
#     def __call__(
#         self,
#         data: Data[T_AssocCallbackResolved],
#         target: T_AssocCallbackTarget,
#     ) -> T_AssocCallbackAssoc: ...


AssocCallbackGrant = Callable[
    [
        Data[ResolvedGrantDocument] | Data[ResolvedGrantUser],
        User | Document,
    ],
    Grant,
]
AssocCallbackAssignment = (
    Callable[
        [
            Data[ResolvedAssignmentDocument] | Data[ResolvedAssignmentCollection],
            Collection | Document,
        ],
        Assignment,
    ]
)
AssocCallback = AssocCallbackGrant | AssocCallbackAssignment

# --------------------------------------------------------------------------- #
# Generic upsert.

T_Upsert = TypeVar(
    "T_Upsert",
    CollectionUpdateSchema,
    CollectionCreateSchema,
    DocumentUpdateSchema,
    DocumentCreateSchema,
    UserUpdateSchema,
    UserCreateSchema,
    GrantCreateSchema,
    EditCreateSchema,
)


class Upsert(WithDelete, Generic[T_Upsert]):

    _upsert_data: T_Upsert | None

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
        upsert_data: T_Upsert | None = None,
    ):
        super().__init__(
            session,
            token,
            method,
            detail=detail,
            api_origin=api_origin,
            force=force,
            access=access,
            delete=delete,
        )
        self._upsert_data = upsert_data

    @property
    def upsert_data(self) -> T_Upsert:
        if (upsert_data := self._upsert_data) is None:
            raise AttributeError("`upsert_data` is not yet set.")
        return upsert_data

    @upsert_data.setter
    def upsert_data(self, v: T_Upsert):
        self._upsert_data = v

    # ----------------------------------------------------------------------- #
    # Helpers

    @property
    def event_common(self) -> Dict[str, Any]:
        kind = KindEvent.create if self.method == H.POST else KindEvent.update
        return dict(**super().event_common, kind=kind)

    @overload
    def assoc(
        self,
        data: Data[ResolvedGrantDocument] | Data[ResolvedGrantUser],
        create_assoc: AssocCallbackGrant,
        *,
        force: bool | None = None,
    ) -> Tuple[
        Data[ResolvedGrantDocument],
        AssocData,
        Update[Grant] | sqaDelete[Grant],
        Type[Grant],
    ]: ...

    # NOTE: Typehints bad when `CallableAssocCallback` is protocol, idk why
    @overload
    def assoc(
        self,
        data: Data[ResolvedAssignmentCollection] | Data[ResolvedAssignmentDocument],
        create_assoc: AssocCallbackAssignment,
        *,
        force: bool | None = None,
    ) -> Tuple[
        Data[ResolvedAssignmentCollection],
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Assignment],
    ]: ...

    def assoc(
        self,
        data: DataResolvedGrant | DataResolvedAssignment,
        create_assoc: AssocCallback,
        *,
        force: bool | None = None,
    ) -> Tuple[
        DataResolvedGrant | DataResolvedAssignment,
        AssocData,
        Update[Assignment] | sqaDelete[Assignment] | Update[Grant] | sqaDelete,
        Type[Assignment] | Type[Grant],
    ]:
        """Symetrically handle forced creation.

        When :attr:`force` is ``True``, lingering assignments staged for
        deletion will be cleaned up by :attr:`delete`. Otherwise, if
        :param:`data` specified exising assignments, an error will be raised.

        :param assoc_args: Common arguments for creating the associations. This
            should be everything that is not specified by :param:`data` or
            :attr:`upsert_data`. For instance, grant should pass key value
            pairs for ``pending_from`` and ``uuid_parent``. This parameter
            should be used for internal values and not user inputs, which
            should be added to `upsert_data`.
        :returns: The active target ids that do not yet have an assignment to
            their source. The requirement that they be active means that doing
            the same `POST` twice should be indempotent.
        """
        session = self.session
        force = force if force is not None else self.force

        # NOTE: No actual deletion here. Deletion occurs in SPM.
        rm_assoc_data, rm_assocs, rm_q, T_assoc = self.delete.try_force(
            data, force=force
        )
        uuid_target_create: Set[str]
        uuid_target_create = data.data.uuid_target.copy()  # type: ignore

        event_rm: Event | None = None
        match self.method:
            case H.POST if not force:
                if rm_assoc_data.uuid_assoc_deleted:
                    msg = "Some targets have existing assignments awaiting "
                    msg += "cleanup. Try this request again with `force=true` "
                    msg += "or make an equivalent `PUT` request."
                    raise HTTPException(
                        400,
                        detail=dict(
                            msg=msg,
                            kind_target=data.data.kind_target.name,
                            kind_source=data.data.kind_source.name,
                            kind_assoc=data.data.kind_assoc.name,
                            uuid_target=list(rm_assoc_data.uuid_target_deleted),
                            uuid_source=data.data.uuid_source,
                            uuid_assoc=list(rm_assoc_data.uuid_assoc_deleted),
                        ),
                    )
                uuid_target_create -= rm_assoc_data.uuid_target_active
            # NOTE: Delete ALL existing, add deleted to created. DO NOT UPDATE
            #       `rm_assoc_data`.
            # NOTE: This should not delete grants belonging to the token holder
            #       otherwise integrity errors will show up later, thus the
            #       re-addition of token holder grants.
            case H.POST | H.PUT:
                if (
                    self.token.uuid == data.data.source.uuid  # type: ignore
                    or self.token.uuid in data.data.uuid_target # type: ignore
                ):
                    msg = (
                        "This request results in user deleting own grants. "
                        "This can only be done by directly deleting these "
                        "grants."
                    )
                    raise HTTPException(400, detail=dict(msg=msg))
                event_rm = self.delete.assoc_event(data, rm_assocs)
                session.add(event_rm)
                session.execute(rm_q)
                session.commit()

                # data, _, rm_q, T_assoc = self.delete.assoc(data, force=force)
            case _:
                raise HTTPException(405)

        targets: Tuple = data.data.target  # type: ignore
        assocs = {
            target.uuid: create_assoc(data, target)  # type: ignore
            for target in targets
            if target.uuid in uuid_target_create
        }
        session.add_all(assocs.values())

        # NOTE: Create event.
        event_common = self.event_common
        event_create = Event(
            **event_common,
            uuid=secrets.token_urlsafe(8),
            uuid_obj=data.data.uuid_source,
            kind_obj=data.data.kind_source,
            children=[
                Event(
                    **event_common,
                    uuid=secrets.token_urlsafe(8),
                    kind_obj=data.data.kind_target,
                    uuid_obj=target_uuid,
                    children=[
                        Event(
                            **event_common,
                            uuid=secrets.token_urlsafe(8),
                            kind_obj=data.data.kind_assoc,
                            uuid_obj=assoc.uuid,
                        )
                    ],
                )
                for target_uuid, assoc in assocs.items()
            ],
        )
        if event_rm is not None:
            event = Event(
                **event_common,
                uuid_obj=data.data.uuid_source,
                kind_obj=data.data.kind_source,
                children=[event_rm, event_create],
            )
            event.kind = KindEvent.upsert
            data.event = event
        else:
            event = event_create

        session.add(event)
        session.commit()
        session.refresh(event)

        data.event = event
        return data, rm_assoc_data, rm_q, T_assoc

    # ----------------------------------------------------------------------- #
    # Assocs
    # @overload
    # def create_assignment(
    #     self,
    #     data: Data[ResolvedAssignmentCollection],
    #     target: Document,
    # ) -> Assignment: ...
    #
    # @overload
    # def create_assignment(
    #     self,
    #     data: Data[ResolvedAssignmentDocument],
    #     target: Collection,
    # ) -> Assignment: ...

    def create_assignment(
        self,
        data: Data[ResolvedAssignmentDocument] | Data[ResolvedAssignmentCollection],
        target: Collection | Document,
    ) -> Assignment:
        id_source_name = f"id_{data.data.kind_source.name}"
        id_target_name = f"id_{data.data.kind_target.name}"
        id_source_value = data.data.source.id  # type: ignore

        kwargs = {
            "uuid": secrets.token_urlsafe(8),
            id_source_name: id_source_value,
            id_target_name: target.id,
        }
        return Assignment(**kwargs)

    def assignment_document(
        self,
        data: Data[ResolvedAssignmentDocument],
    ) -> Data[ResolvedAssignmentDocument]:
        data, *_ = self.assoc(data, self.create_assignment)
        return data

    def assignment_collection(
        self,
        data: Data[ResolvedAssignmentCollection],
    ) -> Data[ResolvedAssignmentCollection]:
        data, *_ = self.assoc(data, self.create_assignment)
        return data

    # @overload
    # def create_grant(
    #     self,
    #     data: Data[ResolvedGrantDocument],
    #     target: User,
    # ) -> Grant: ...
    #
    # @overload
    # def create_grant(
    #     self,
    #     data: Data[ResolvedGrantUser],
    #     target: Document,
    # ) -> Grant: ...

    def create_grant(
        self,
        data: Data[ResolvedGrantDocument] | Data[ResolvedGrantUser],
        target: Document | User,
    ) -> Grant:
        # NOTE: Grants should be indexed by uuids of documents.
        match data.data.kind_source:
            case KindObject.user:
                # NOTE: Permission of granter since they are inviting a user in
                #       this case. This means that the invitor (a user who 
                #       already owns the document) will be the one responsible
                #       for the grants creation.
                grant_parent = Grant.resolve_from_target(
                    self.session,
                    data.token_user or self.token_user,
                    {target.uuid}
                )
                if not (n:=len(grant_parent)):
                    detail = dict(
                        msg="No such grant.",
                        uuid_target=target.uuid,
                        uuid_source=data.data.source.uuid,
                        kind_target=data.data.kind_target,
                        kind_source=data.data.kind_source,
                    )
                    raise HTTPException(403, detail=detail)
                elif n > 1:
                    raise HTTPException(500, detail="Granter has too many grants.")

                grant_parent_uuid = grant_parent[0].uuid
                pending_from = PendingFrom.grantee
            case KindObject.document:
                grant_parent_uuid = None
                # ^^^^^^^^^^^^^^^^^ Assigned later by granter who accepts the 
                #                   request. Grant of the granter to remove 
                #                   this from pending state will be created 
                #                   later.
                pending_from = PendingFrom.granter
            case bad:
                raise ValueError(f"Invalid source `{bad}`.")

        id_source_name = f"id_{data.data.kind_source.name}"
        id_target_name = f"id_{data.data.kind_target.name}"
        id_source_value = data.data.source.id  # type: ignore

        kwargs = {
            "uuid": secrets.token_urlsafe(8),
            "uuid_parent": grant_parent_uuid,
            "pending_from": pending_from,
            "pending": True,
            id_source_name: id_source_value,
            id_target_name: target.id,
        }
        return Grant(**kwargs, **self.upsert_data.model_dump())

    def grant_user(
        self,
        data: Data[ResolvedGrantUser],
    ) -> Data[ResolvedGrantUser]:
        data, *_ = self.assoc(data, self.create_grant)
        return data

    def grant_document(
        self,
        data: Data[ResolvedGrantDocument],
    ) -> Data[ResolvedGrantDocument]:
        data, *_ = self.assoc(data, self.create_grant)
        return data

    a_assignment_document = with_access(Access.assignment_document)(assignment_document)
    a_assignment_collection = with_access(Access.assignment_collection)(
        assignment_collection
    )
    a_grant_document = with_access(Access.grant_document)(grant_document)
    a_grant_user = with_access(Access.grant_user)(grant_user)

    # ----------------------------------------------------------------------- #
    # Others

    def user(self, data: Data[ResolvedUser]) -> Data[ResolvedUser]:
        ...

    def collection(
        self,
        data: Data[ResolvedCollection],
    ) -> Data[ResolvedCollection]:
        ...


    def document(
        self,
        data: Data[ResolvedDocument],
    ) -> Data[ResolvedDocument]:
        ...

    def edit(self, data: Data[ResolvedEdit]) -> Data[ResolvedEdit]:
        ...


