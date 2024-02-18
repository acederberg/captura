import secrets
import json
from functools import cached_property
from http import HTTPMethod
from typing import Any, Callable, Dict, Generic, Set, Tuple, Type, TypeVar, overload

from app import __version__, util
from app.auth import Token
from app.models import (Assignment, Collection, Document, Event, Grant, KindEvent,
                        KindObject, ResolvableMultiple, ResolvableSingular,
                        ResolvableSourceAssignment, ResolvableTargetAssignment,
                        Tables, User)
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
        access: Access| None = None,
        delete: Delete | None = None,
        upsert_data: T_Upsert = None,
    ):
        super().__init__(
            session,
            token,
            method,
            detail=detail,
            api_origin=api_origin,
            force=force,
            access=access,
            delete=delete
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

    # @overload
    # def assoc(self, data: Data[ResolvedAssignmentCollection]) -> Data[ResolvedAssignmentCollection]: ...  # type: ignore
    #
    # @overload
    # def assoc(self, data: Data[ResolvedAssignmentDocument]) -> Data[ResolvedAssignmentDocument]: ...  # type: ignore
    #
    # @overload
    # def assoc(self, data: Data[ResolvedGrantUser]) -> Data[ResolvedGrantUser]: ...
    #
    # @overload
    # def assoc(
    #     self, data: Data[ResolvedGrantDocument]
    # ) -> Data[ResolvedGrantDocument]: ...
    @overload
    def assoc(
        self,
        data: Data[ResolvedGrantUser],
        assoc_args_callback: Callable[[Dict[str, Any]], Dict[str, Any]] = lambda v: v,
        *,
        force: bool = False,
    ) -> Tuple[
        Data[ResolvedGrantUser],
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Grant],
    ]: ...

    @overload
    def assoc(
        self,
        data: Data[ResolvedGrantDocument],
        assoc_args_callback: Callable[[Dict[str, Any]], Dict[str, Any]] = lambda v: v,
        *,
        force: bool = False,
    ) -> Tuple[
        Data[ResolvedGrantDocument],
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Grant],
    ]: ...

    @overload
    def assoc(
        self,
        data: Data[ResolvedAssignmentDocument],
        assoc_args_callback: Callable[[Dict[str, Any]], Dict[str, Any]] = lambda v: v,
        *,
        force: bool = False,
    ) -> Tuple[
        Data[ResolvedAssignmentDocument],
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Assignment],
    ]: ...

    @overload
    def assoc(
        self,
        data: Data[ResolvedAssignmentCollection],
        assoc_args_callback: Callable[[Dict[str, Any]], Dict[str, Any]] = lambda v: v,
        *,
        force: bool = False,
    ) -> Tuple[
        Data[ResolvedAssignmentCollection],
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Assignment],
    ]: ...


    def assoc(
        self, 
        data: DataResolvedGrant | DataResolvedAssignment, 
        assoc_args_callback: Callable[[Dict[str, Any]], Dict[str, Any]] = lambda v: v,
        *,
        force: bool = False,
    ) -> Tuple[
        DataResolvedGrant | DataResolvedAssignment,
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Assignment],
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
        print("====================================================")
        print("force", force)
        print("self.force", self.force)

        # NOTE: No actual deletion here. Deletion occurs in SPM.
        rm_assoc_data, rm_assocs, rm_q, T_assoc = self.delete.try_force(data, force=force)
        uuid_target_create: Set[str]
        uuid_target_create = data.data.uuid_target.copy()  # type: ignore
        uuid_target_create -= rm_assoc_data.uuid_target_active

        print('uuid_target_active', rm_assoc_data.uuid_target_active)
        print('uuid_target_deleted', rm_assoc_data.uuid_target_deleted)
        print('uuid_assoc_active', rm_assoc_data.uuid_assoc_active)
        print('uuid_assoc_deleted', rm_assoc_data.uuid_assoc_deleted)


        match self.method:
            case H.POST if not force:
                # print(H.POST, self.force)
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
            # NOTE: Delete existing, add deleted to created.
            case H.POST | H.PUT:
                data.event = self.delete.assoc_event(data, rm_assocs)
                print("rm_q", "---------------------------------------------")
                util.sql(session, rm_q)
                # input(1)

                session.add(data.event)
                session.execute(rm_q)
                session.commit()
                # input(2)
                print('uuid_target_create', uuid_target_create)
                print('rm_assoc_data.uuid_target_deleted', rm_assoc_data.uuid_target_deleted)
                uuid_target_create |= rm_assoc_data.uuid_target_deleted
                print('uuid_target_create', uuid_target_create)
                data, rm_assoc_data, rm_q, T_assoc = self.delete.assoc(data, force=force)
            case _:
                raise HTTPException(405)

        # NOTE: Create assocs. DO NOT TRY TO USE `getattr` on `assoc` for 
        #       `uuid_target_attr_name`.
        id_source_name = f"id_{data.data.kind_source.name}"
        id_target_name = f"id_{data.data.kind_target.name}"

        id_source_value = data.data.source.id # type: ignore
        targets: Tuple = data.data.target  # Type: ignore
        print("--------------------")
        print(self.upsert_data)
        print("--------------------")
        assocs = {
            target.uuid: T_assoc(
                **assoc_args_callback({
                    id_source_name: id_source_value,
                    id_target_name: target.id,
                    "uuid": secrets.token_urlsafe(8),
                    **self.upsert_data.model_dump(),
                })
            )
            for target in targets
            if target.uuid in uuid_target_create
        }
        session.add_all(assocs.values())

        # NOTE: Create event.
        event_common = self.event_common
        event = Event(
            **event_common,
            uuid_obj=data.data.uuid_source,
            kind_obj=data.data.kind_source,
            children=[
                Event(
                    **event_common,
                    kind_obj=data.data.kind_target,
                    uuid_obj=target_uuid,
                    children=[
                        Event(
                            **event_common,
                            kind_obj=data.data.kind_assoc,
                            uuid_obj=assoc.uuid,
                        )
                    ],
                )
                for target_uuid, assoc in assocs.items()
            ],
        )
        session.add(event)
        if data.event is not None:
            event_rm, data.event = data.event, None
            event.children.insert(0, event_rm)
            data.event = event
        else:
            data.event = event

        # input(3)
        session.commit()

        return data, rm_assoc_data, rm_q, T_assoc

    # ----------------------------------------------------------------------- #
    # Assocs

    def assignment_document(
        self,
        data: Data[ResolvedAssignmentDocument],
    ) -> Data[ResolvedAssignmentDocument]:
        data, *_ = self.assoc(data)
        return data

    def assignment_collection(
        self,
        data: Data[ResolvedAssignmentCollection],
    ) -> Data[ResolvedAssignmentCollection]:
        data, *_ = self.assoc(data)
        return data

    def grant_user(
        self,
        data: Data[ResolvedGrantUser],
    ) -> Data[ResolvedGrantUser]:
        data, *_ = self.assoc(data)
        return data

    def grant_document(
        self,
        data: Data[ResolvedGrantDocument],
    ) -> Data[ResolvedGrantDocument]:
        data, *_ = self.assoc(data)
        return data

    a_assignment_document = with_access(Access.assignment_document)(assignment_document)
    a_assignment_collection = with_access(Access.assignment_collection)(assignment_collection)
    a_grant_document = with_access(Access.grant_document)(grant_document)
    a_grant_user = with_access(Access.grant_user)(grant_user)

    # ----------------------------------------------------------------------- #
    # Others

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
    def edit(
        self,
        data: Data[ResolvedEdit],
    ) -> Data[ResolvedEdit]: ...

