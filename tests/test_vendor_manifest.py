"""Checksum manifest of `bin/lib/` - `tools/hash_manifest.py` (A-6).

The manifest describes **what `tools/vendor.sh` installs**. The pruning done by
`vendor.sh` already removes `__pycache__` and `*.pyc`; the verification walk must apply
the same exclusion. Without it, importing the vendored SDK - that is, running a test, a
diagnostic or the command itself - creates `.pyc` files under `bin/lib/` and fails the
verifier on a false positive, pointing the reader at a full rebuild.

The tests operate on a temporary tree: they never write into the `bin/lib/` of the
repository and do not depend on its compilation state.
"""

import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest

from . import REPO_ROOT

_TOOLS = os.path.join(REPO_ROOT, "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

import hash_manifest  # noqa: E402


def _silenced(function):
    """Call `function()` while absorbing its output: `write` and `check` report on
    stdout/stderr, which has no business in the test report."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
        io.StringIO()
    ):
        return function()


class TemporaryTree(object):
    """Point `hash_manifest` at a throwaway tree, for the duration of the test."""

    def __enter__(self):
        self.root = tempfile.mkdtemp(prefix="acl_manifest_")
        self._lib, self._manifest = hash_manifest.LIB, hash_manifest.MANIFEST
        hash_manifest.LIB = self.root
        hash_manifest.MANIFEST = os.path.join(self.root, "MANIFEST.sha256")
        return self

    def __exit__(self, *exc):
        hash_manifest.LIB, hash_manifest.MANIFEST = self._lib, self._manifest
        shutil.rmtree(self.root, ignore_errors=True)
        return False

    def write_file(self, relative, content=b"content"):
        path = os.path.join(self.root, *relative.split("/"))
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(path, "wb") as handle:
            handle.write(content)
        return path


class ManifestIgnoresCompilationArtifactsTest(unittest.TestCase):
    """A-6: a `__pycache__` must neither enter the manifest nor fail it."""

    def test_the_walk_ignores_pycache_and_pyc(self):
        with TemporaryTree() as tree:
            tree.write_file("splunklib/__init__.py")
            tree.write_file("splunklib/client.py")
            tree.write_file("splunklib/__pycache__/__init__.cpython-312.pyc")
            tree.write_file("splunklib/__pycache__/client.cpython-312.pyc")
            tree.write_file("splunklib/client.pyo")

            recorded = sorted(relative for relative, _ in hash_manifest._entries())

        self.assertEqual(recorded, ["splunklib/__init__.py", "splunklib/client.py"])

    def test_check_stays_compliant_after_a_pycache_appears(self):
        """The real-world scenario: `check` passes, the SDK gets imported, `check` must
        still pass.

        This is the exact wording of A-6 - the verifier was failed by the very act of
        using what it verifies.
        """
        with TemporaryTree() as tree:
            tree.write_file("splunklib/__init__.py")
            tree.write_file("splunklib/searchcommands/__init__.py")
            self.assertEqual(_silenced(hash_manifest.write), 0)
            self.assertEqual(_silenced(hash_manifest.check), 0)

            # An import of the vendored SDK: the interpreter drops its artifacts.
            tree.write_file("splunklib/__pycache__/__init__.cpython-312.pyc")
            tree.write_file(
                "splunklib/searchcommands/__pycache__/__init__.cpython-312.pyc"
            )

            self.assertEqual(_silenced(hash_manifest.check), 0)

    def test_a_real_divergence_is_still_detected(self):
        """The exclusion must not blunt the check: an added file fails it."""
        with TemporaryTree() as tree:
            tree.write_file("splunklib/__init__.py")
            self.assertEqual(_silenced(hash_manifest.write), 0)

            tree.write_file("splunklib/backdoor.py")
            self.assertEqual(_silenced(hash_manifest.check), 1)

            os.remove(os.path.join(tree.root, "splunklib", "backdoor.py"))
            tree.write_file("splunklib/__init__.py", b"modified content")
            self.assertEqual(_silenced(hash_manifest.check), 1)


if __name__ == "__main__":
    unittest.main()
