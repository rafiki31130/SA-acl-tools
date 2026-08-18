"""Business core of the `editacl` search command.

Import rule, mechanically checkable and checked by `tests/test_layering.py`:
**no file in this package mentions a search-command SDK, and none imports `socket`,
`http` or `urllib.request`, with the sole exception of `acltools.rest`.**

That rule is what makes the whole of the business logic - normalization, merge,
endpoint resolution, journal serialization, state machine - testable outside Splunk,
with no instance and no network, as spec section 11.1 requires. It is not a
development convenience: it is the only way to exhaustively exercise an irreversible
operation whose rollback macro is the only safety net.
"""

__version__ = "1.1.0"
