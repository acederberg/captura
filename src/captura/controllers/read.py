# =========================================================================== #
from http import HTTPMethod
from random import shuffle
from typing import Any, Dict, List, Type, TypeVar, overload

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

# --------------------------------------------------------------------------- #
# from captura import util
from captura.auth import Token
from captura.controllers.access import Access
from captura.controllers.base import BaseController
from captura.fields import Singular
from captura.models import Collection, Document, Tables, User
from captura.schemas import (
    CollectionSearchSchema,
    DocumentSearchSchema,
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
    ) -> List[User]: ...

    @overload
    def search_user(
        self,
        user: User,
        param: DocumentSearchSchema,
    ) -> List[Document]: ...

    @overload
    def search_user(
        self,
        user: User,
        param: CollectionSearchSchema,
    ) -> List[Collection]: ...

    def search_user(
        self,
        user: User,
        param: UserSearchSchema | DocumentSearchSchema | CollectionSearchSchema,
    ) -> List[User] | List[Document] | List[Collection]:
        if param.kind_mapped is None:
            raise HTTPException(500)

        singular = Singular(param.kind_mapped.name)

        T_kind: Type[User] | Type[Document] | Type[Collection]
        T_kind = Tables[singular.name].value  # type: ignore[reportGeneralTypeErrors]

        q = T_kind.q_search(
            user.uuid,
            param.uuids,
            all_=True,
            name_like=param.name_like,
            description_like=param.description_like,
            limit=param.limit,
        )

        if param.randomize and param.uuids is None:
            # if param.limit is None or param.limit > 25:
            #     msg = "Limit must be less than `25` to randomize."
            #     raise HTTPException(400, detail=msg)

            q = q.order_by(func.random())

        res: List[User] | List[Document] | List[Collection]
        res = list(self.session.scalars(q))

        if param.randomize and param.uuids is not None:
            shuffle(res)

        return res
