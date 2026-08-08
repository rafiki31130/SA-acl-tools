"""Unit test suite of spec section 11.1: runs outside Splunk, no instance, no network.

Replay command, from the root of the repository:

    python -m unittest discover -s tests -t . -v

No development dependency: `unittest` from the standard library is enough. The tests
import `bin/acltools` directly, **without ever loading `bin/lib`**, which is the
practical check that the core does not depend on the SDK.
"""

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BIN = os.path.join(_REPO_ROOT, "bin")
if _BIN not in sys.path:
    sys.path.insert(0, _BIN)

REPO_ROOT = _REPO_ROOT
BIN_DIR = _BIN
