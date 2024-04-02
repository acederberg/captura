# =========================================================================== #
import json
from http import HTTPMethod
from typing import Any, Dict, Tuple, Type, TypeVar, overload

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

# --------------------------------------------------------------------------- #
from app import util
from app.auth import Token
from app.controllers.access import Access
from app.controllers.base import BaseController
from app.fields import Singular
from app.models import Collection, Document, Edit, Tables, User
from app.schemas import (
    CollectionSearchSchema,
    DocumentSearchSchema,
    EditSearchSchema,
    UserSearchSchema,
)

T_ReadParam = TypeVar(
    "T_ReadParam",
)


class Read(BaseController):
    """DO NOT USE THIS FOR GET BY ID, USING :class:`Access` SHOULD BE ENOUGH.

    This is for more complicated methods and will not follow the pattern set
    by :class:`Access`, :class:`Delete`, :class:`Update`, or :class:`Create`.
    """

    access: Access

    def __init__(
        self,
        session: Session,
        token: Token | Dict[str, Any] | None,
        method: HTTPMethod | str,
        *,
        access: Access | None = None,
    ):
        if method != HTTPMethod.GET:
            raise ValueError("`method` must be `GET`.")

        super().__init__(session, token, method)
        if access is None:
            access = self.then(Access)
        self.access = access

    # ======================================================================= #

    @overload
    def search_user(
        self,
        user: User,
        param: UserSearchSchema,
    ) -> Tuple[User, ...]:
        ...

    @overload
    def search_user(
        self,
        user: User,
        param: DocumentSearchSchema,
    ) -> Tuple[Document, ...]:
        ...

    @overload
    def search_user(
        self,
        user: User,
        param: CollectionSearchSchema,
    ) -> Tuple[Collection, ...]:
        ...

    # @overload
    # def search_user(
    #     self,
    #     user: User,
    #     param: EditSearchSchema,
    # ) -> Tuple[Edit, ...]:
    #     ...

    def search_user(
        self,
        user: User,
        param: (
            UserSearchSchema
            | DocumentSearchSchema
            | CollectionSearchSchema
            # | EditSearchSchema
        ),
    ) -> (
        Tuple[User, ...]
        | Tuple[Document, ...]
        | Tuple[Collection, ...]
        # | Tuple[Edit, ...]
    ):
        if param.kind_mapped is None:
            raise HTTPException(500)

        singular = Singular(param.kind_mapped.name)

        T_kind: Type[User] | Type[Document] | Type[Collection]  # | Type[Edit]
        T_kind = Tables[singular.name].value  # type: ignore[reportGeneralTypeErrors]

        q = T_kind.q_search(
            user.uuid,
            param.uuids,
            all_=True,
            name_like=param.name_like,
            description_like=param.description_like,
            limit=param.limit,
        ) 

        if param.randomize:
            q = q.order_by(func.random())

        return tuple(self.session.scalars(q))
