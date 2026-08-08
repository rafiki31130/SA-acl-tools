"""Layer separation: the import rule of spec section 1.2, checked mechanically.

This is the test that keeps testability outside Splunk from degrading over the
iterations. Without it the rule is nothing but an intention in a comment: one import
hastily added to `merge.py` is enough to make section 11.1 inapplicable and to stop the
merge matrix from being provable on a machine with no instance.
"""

import ast
import os
import unittest

from . import BIN_DIR

PACKAGE_DIR = os.path.join(BIN_DIR, "acltools")

#: The only module allowed to speak HTTP and to open a socket.
ALLOWED_NETWORK_MODULE = "rest.py"

#: Modules the core may not import, outside `rest.py`.
FORBIDDEN_IMPORTS = ("socket", "http", "urllib.request", "urllib.error", "ssl")

#: Text patterns forbidden in the core, with no module exception: the search command
#: SDK has no place there. The name is reassembled so that this test file is not itself
#: a counter-example if it were ever moved.
FORBIDDEN_TEXT = ("splunk" + "lib",)


def _python_files():
    for name in sorted(os.listdir(PACKAGE_DIR)):
        if name.endswith(".py"):
            yield name, os.path.join(PACKAGE_DIR, name)


def _imported_modules(path):
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                modules.add(node.module)
    return modules


class LayeringTest(unittest.TestCase):

    def test_the_package_exists_and_is_not_empty(self):
        files = list(_python_files())
        self.assertGreaterEqual(len(files), 10)
        self.assertIn(ALLOWED_NETWORK_MODULE, [name for name, _ in files])

    def test_no_core_module_imports_the_network_except_rest(self):
        for name, path in _python_files():
            if name == ALLOWED_NETWORK_MODULE:
                continue
            with self.subTest(module=name):
                modules = _imported_modules(path)
                for forbidden in FORBIDDEN_IMPORTS:
                    root = forbidden.split(".")[0]
                    offenders = [
                        m for m in modules
                        if m == forbidden or m == root or m.startswith(forbidden + ".")
                    ]
                    # `urllib.parse` is allowed: it is string computation, not network
                    # access. Only the network branches of urllib are proscribed.
                    offenders = [
                        m for m in offenders if not m.startswith("urllib.parse")
                    ]
                    if root == "urllib":
                        offenders = [
                            m for m in offenders
                            if m in ("urllib", "urllib.request", "urllib.error")
                        ]
                    self.assertEqual(
                        offenders, [],
                        "%s imports %r: the import rule of section 1.2 forbids the "
                        "network outside acltools/rest.py" % (name, offenders),
                    )

    def test_no_core_file_mentions_the_sdk(self):
        for name, path in _python_files():
            with self.subTest(module=name):
                with open(path, encoding="utf-8") as handle:
                    source = handle.read()
                for pattern in FORBIDDEN_TEXT:
                    self.assertNotIn(
                        pattern, source,
                        "%s mentions %r: the core must stay importable without the SDK"
                        % (name, pattern),
                    )

    def test_the_core_imports_without_bin_lib_on_the_path(self):
        """The tests never insert `bin/lib` into `sys.path`: the mere fact that the
        suite runs proves that the core does not depend on the vendored SDK."""
        import sys

        lib = os.path.join(BIN_DIR, "lib")
        self.assertNotIn(lib, sys.path)

        import acltools.endpoint  # noqa: F401
        import acltools.journal  # noqa: F401
        import acltools.mapping  # noqa: F401
        import acltools.merge  # noqa: F401
        import acltools.normalize  # noqa: F401
        import acltools.pipeline  # noqa: F401
        import acltools.preflight  # noqa: F401

    def test_the_wrapper_compiles_without_the_sdk(self):
        """`bin/editacl.py` is not importable without the SDK, which is the point, but
        it must at least compile, and its `sys.path` insertion must come before the
        first import of the SDK."""
        path = os.path.join(BIN_DIR, "editacl.py")
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        compile(source, path, "exec")

        tree = ast.parse(source, filename=path)
        syspath_line = None
        sdk_line = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and syspath_line is None:
                if ast.unparse(node.func) == "sys.path.insert":
                    syspath_line = node.lineno
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("splunk" + "lib") and sdk_line is None:
                    sdk_line = node.lineno
        self.assertIsNotNone(syspath_line, "no insertion into sys.path")
        self.assertIsNotNone(sdk_line, "no import of the SDK")
        self.assertLess(
            syspath_line, sdk_line,
            "bin/lib must be at the head of sys.path BEFORE the first SDK import",
        )

    def test_the_wrapper_carries_no_business_rule(self):
        """The adapter wires, it does not decide: none of the decision functions of the
        core is redefined there."""
        path = os.path.join(BIN_DIR, "editacl.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        defined = {
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        forbidden = {
            "merge", "is_noop", "normalize_roles", "validate_roles", "parse_fields",
            "build_object_path", "encode_title_segment", "resolve_handler_path",
            "build_intent_record", "build_outcome_record",
        }
        self.assertEqual(defined & forbidden, set())

    def test_the_core_uses_no_third_party_dependency(self):
        """No library outside the standard library, on any module."""
        allowed = {
            "ast", "csv", "json", "logging", "logging.handlers", "os", "re", "ssl",
            "sys", "time", "typing", "dataclasses", "datetime", "urllib",
            "urllib.parse", "urllib.request", "urllib.error", "collections",
            "collections.abc",
        }
        for name, path in _python_files():
            with self.subTest(module=name):
                for module in _imported_modules(path):
                    if module.startswith("."):
                        continue
                    root = module.split(".")[0]
                    if root == "acltools":
                        continue
                    self.assertIn(
                        module if module in allowed else root, allowed,
                        "%s imports %r, outside the allowed standard library"
                        % (name, module),
                    )


if __name__ == "__main__":
    unittest.main()
