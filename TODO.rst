Purpose of this Document
###############################################################################

This document will be used as a list of 'nice to haves' for later as creating
and deploying initial release first.

Items
###############################################################################

- Tests should move to `dummy` based solutions. Unfortunately many of the
  initial tests no longer apply so this will likely be done to some degree
  right now.
- Self assembling CLI requests from ``openapi.json``? It is possible seeing that
  swagger can generate examples for ``cURL``, ``python``, etc.
- Move ``token`` and ``token_user`` to :class:`Data`.
- Make a ``TypedDict`` that can be used to store the keywords shared between
  methods of :class:`Access` and the various query constructor methods (the
  model method prefixed with ``q``).
