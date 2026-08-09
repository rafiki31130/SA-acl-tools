"""URI resolution and reconstruction (sections 5.2, 10.4).

Reconstruction is mandatory and not negotiable: the native `id` field double-encodes
the slash but not the other special characters, so it is not reusable as a URI as it
stands.
"""

import inspect
import unittest

from acltools.endpoint import (
    FIXED_CONTEXT,
    TITLE_ENCODING_MODE,
    build_object_path,
    build_object_url,
    encode_namespace_segment,
    encode_title_segment,
    handler_path_from_id,
    is_fixed_context,
    namespace_owner_from_id,
    resolve_handler_path,
)
from acltools.errors import EventRejected

from .helpers import FIXTURE_MAPPING


class TitleEncodingTest(unittest.TestCase):
    """One rule, settled empirically: plain `%`-encoding, `safe=''`.

    The four character classes of section 10.4 are covered one by one. Double encoding
    is an asymmetric trap: it works for `/` alone and breaks space, accent and percent.
    """

    def test_the_mode_retained_is_single_encoding(self):
        self.assertEqual(TITLE_ENCODING_MODE, "single")

    def test_space_class(self):
        self.assertEqual(encode_title_segment("My search"), "My%20search")

    def test_slash_class_with_no_special_treatment(self):
        self.assertEqual(
            encode_title_segment("Report/Monthly"), "Report%2FMonthly"
        )

    def test_accented_character_class_encoded_utf8_byte_by_byte(self):
        self.assertEqual(
            encode_title_segment("Summary report"), "Summary%20report"
        )
        self.assertEqual(
            encode_title_segment("éàü"), "%C3%A9%C3%A0%C3%BC"
        )

    def test_percent_class(self):
        self.assertEqual(encode_title_segment("Rate 100%"), "Rate%20100%25")

    def test_other_reserved_characters_encoded(self):
        self.assertEqual(encode_title_segment("a+b&c=d"), "a%2Bb%26c%3Dd")

    def test_namespace_segment_encoded_the_same_way(self):
        self.assertEqual(encode_namespace_segment("my app"), "my%20app")


class BuildObjectPathTest(unittest.TestCase):

    def test_reconstructed_path_without_the_acl_suffix(self):
        path = build_object_path("my_app", "saved/searches", "My search")
        self.assertEqual(
            path, "/servicesNS/nobody/my_app/saved/searches/My%20search"
        )
        self.assertFalse(path.endswith("/acl"))
        self.assertNotIn("/acl", path)

    def test_handler_path_is_not_reencoded(self):
        path = build_object_path("my_app", "saved/searches", "object")
        self.assertIn("saved/searches", path)
        self.assertNotIn("saved%2Fsearches", path)

    def test_url_prefixed_by_the_splunkd_base_with_no_hardcoded_host(self):
        path = build_object_path("my_app", "saved/searches", "object")
        url = build_object_url("https://base.invalid:0/", path)
        self.assertEqual(url, "https://base.invalid:0" + path)


class FixedContextAddressingTest(unittest.TestCase):
    """Section 5.2, D-25: addressing **never** carries an owner.

    What the fixed context corrects: v1 addressed by `eai:acl.owner`, yet a private
    object **masks** a homonymous shared object in the namespace of its holder. If the
    owner of a shared object also held a private object of the same name in the same
    application, the command reached the **private** one and wrote its ACL: `200` on
    the GET, merge computed, POST completed, line reported as `updated`. A silent write
    on the wrong target, which neither acceptance testing nor two audits had detected,
    for want of having measured namespace resolution.
    """

    def test_the_context_is_always_nobody(self):
        self.assertEqual(FIXED_CONTEXT, "nobody")
        path = build_object_path("my_app", "saved/searches", "object")
        self.assertTrue(path.startswith("/servicesNS/nobody/my_app/"))

    def test_the_signature_exposes_no_owner(self):
        """A **structural** guarantee: there is no parameter to fill in wrongly.

        A future caller therefore cannot reintroduce the v1 defect by inadvertence:
        the function would refuse the argument.
        """
        parameters = list(
            inspect.signature(build_object_path).parameters
        )
        self.assertEqual(parameters, ["app", "handler_path", "title"])
        for name in parameters:
            self.assertNotIn("owner", name)

    def test_two_homonymous_objects_of_different_owners_have_the_same_uri(self):
        """The corollary of the fixed context: the address depends only on the
        application and on the name. That is what guarantees the **shared** object is
        reached, whoever holds it, and never anybody's private homonym."""
        first = build_object_path("my_app", "saved/searches", "homonymous_object")
        second = build_object_path("my_app", "saved/searches", "homonymous_object")
        self.assertEqual(first, second)
        self.assertNotIn("an_owner", first)

    def test_the_wildcard_context_is_not_the_one_retained(self):
        """The wildcard refuses the write, and on two homonymous objects it returns two
        entries on a single-object path: a client reading the first would choose
        blindly."""
        self.assertNotEqual(FIXED_CONTEXT, "-")
        self.assertNotIn(
            "/servicesNS/-/",
            build_object_path("my_app", "saved/searches", "object"),
        )


class HandlerPathFromIdTest(unittest.TestCase):

    def test_usable_native_id(self):
        self.assertEqual(
            handler_path_from_id(
                "https://base.invalid:0/servicesNS/nobody/my_app/saved/searches/"
                "My%20search"
            ),
            "saved/searches",
        )

    def test_id_pointing_at_admin_directory_is_discarded(self):
        self.assertIsNone(
            handler_path_from_id(
                "https://base.invalid:0/servicesNS/-/-/admin/directory/My%20search"
            )
        )

    def test_malformed_id_is_discarded(self):
        self.assertIsNone(handler_path_from_id("not-a-uri"))

    def test_id_without_the_servicesns_marker_is_discarded(self):
        self.assertIsNone(
            handler_path_from_id("https://base.invalid:0/services/saved/searches/object")
        )

    def test_id_absent_or_empty(self):
        self.assertIsNone(handler_path_from_id(None))
        self.assertIsNone(handler_path_from_id("   "))

    def test_last_segment_dropped_the_name_comes_from_title(self):
        """The title double-encoded by `id` must never serve as an object name."""
        self.assertEqual(
            handler_path_from_id(
                "https://base.invalid:0/servicesNS/nobody/my_app/saved/searches/"
                "Report%252FMonthly"
            ),
            "saved/searches",
        )

    def test_host_and_port_of_id_are_discarded(self):
        path = handler_path_from_id(
            "https://other-member.invalid:0/servicesNS/nobody/my_app/data/ui/views/v"
        )
        self.assertEqual(path, "data/ui/views")

    def test_an_id_carrying_a_traversal_is_discarded(self):
        """A-5: a forged `id` must not step out of the reconstructed namespace.

        On Splunk 9.4.6 the request ended in a 404 emitted by splunkd, which treats
        `..` as an unknown handler action. Containment is now carried by the tool
        itself: the `handler_path` is discarded at the source.
        """
        for id_value in (
            "https://base.invalid:0/servicesNS/nobody/my_app/"
            "a/../../../services/authentication/users/object",
            "https://base.invalid:0/servicesNS/nobody/my_app/"
            "saved/../admin/directory/object",
        ):
            with self.subTest(id_value=id_value):
                self.assertIsNone(handler_path_from_id(id_value))


class ResolveHandlerPathTest(unittest.TestCase):

    def test_the_id_route_has_priority(self):
        handler = resolve_handler_path(
            "https://base.invalid:0/servicesNS/nobody/my_app/saved/searches/object",
            "views",
            FIXTURE_MAPPING,
        )
        self.assertEqual(handler, "saved/searches")

    def test_id_on_admin_directory_falls_back_to_the_table(self):
        handler = resolve_handler_path(
            "https://base.invalid:0/servicesNS/-/-/admin/directory/object",
            "savedsearch",
            FIXTURE_MAPPING,
        )
        self.assertEqual(handler, "saved/searches")

    def test_absent_id_falls_back_to_the_table(self):
        handler = resolve_handler_path(None, "views", FIXTURE_MAPPING)
        self.assertEqual(handler, "data/ui/views")

    def test_malformed_id_falls_back_to_the_table(self):
        handler = resolve_handler_path(
            "not-a-uri", "views", FIXTURE_MAPPING
        )
        self.assertEqual(handler, "data/ui/views")

    def test_id_with_a_traversal_falls_back_to_the_table(self):
        """A-5: the refusal does not open a functional hole - the table takes over."""
        handler = resolve_handler_path(
            "https://base.invalid:0/servicesNS/nobody/my_app/"
            "saved/../../services/authentication/users/object",
            "views",
            FIXTURE_MAPPING,
        )
        self.assertEqual(handler, "data/ui/views")

    def test_unknown_eai_type_rejects_with_no_heuristic(self):
        with self.assertRaises(EventRejected) as raised:
            resolve_handler_path(None, "nonexistent_type", FIXTURE_MAPPING)
        self.assertEqual(raised.exception.status, "rejected")
        self.assertEqual(
            raised.exception.error, "unresolved_endpoint:nonexistent_type"
        )

    def test_neither_id_nor_eai_type(self):
        with self.assertRaises(EventRejected) as raised:
            resolve_handler_path(None, None, FIXTURE_MAPPING)
        self.assertEqual(raised.exception.error, "unresolved_endpoint:")

    def test_family_without_a_native_eai_type_resolved_by_id(self):
        """The seven families missing from `admin/directory` emit no `eai:type` on
        their native endpoint: `id` is the only route available there."""
        handler = resolve_handler_path(
            "https://base.invalid:0/servicesNS/nobody/my_app/data/lookup-table-files/"
            "table.csv",
            None,
            FIXTURE_MAPPING,
        )
        self.assertEqual(handler, "data/lookup-table-files")


class NamespaceCarriedByIdTest(unittest.TestCase):
    """Section 3.5, D-34: the namespace carried by `id` is a platform datum.

    Splunkd emits `/servicesNS/nobody/...` for a shared object and
    `/servicesNS/<owner>/...` for a private one. It is the only designation the command
    has when the result set does not carry the current sharing scope, and it is
    **emitted**, never reconstructed: nothing here assumes a naming convention that we
    would be laying down.
    """

    SHARED = (
        "https://base.invalid:0/servicesNS/nobody/my_app/saved/searches/"
        "witness_object"
    )
    PRIVATE = (
        "https://base.invalid:0/servicesNS/an_operator/my_app/saved/searches/"
        "witness_object"
    )

    def test_a_shared_object_carries_the_fixed_context(self):
        self.assertEqual(namespace_owner_from_id(self.SHARED), FIXED_CONTEXT)
        self.assertTrue(is_fixed_context(namespace_owner_from_id(self.SHARED)))

    def test_a_private_object_carries_a_nominative_namespace(self):
        self.assertEqual(namespace_owner_from_id(self.PRIVATE), "an_operator")
        self.assertFalse(is_fixed_context(namespace_owner_from_id(self.PRIVATE)))

    def test_the_two_homonyms_differ_only_by_that_segment(self):
        """The substantive point: same title, same app, same family - only the
        namespace tells the private object from the shared one, and it is the platform
        that writes it."""
        self.assertEqual(
            handler_path_from_id(self.PRIVATE), handler_path_from_id(self.SHARED)
        )
        self.assertNotEqual(
            namespace_owner_from_id(self.PRIVATE),
            namespace_owner_from_id(self.SHARED),
        )

    def test_a_relative_path_is_accepted(self):
        self.assertEqual(
            namespace_owner_from_id(
                "/servicesNS/an_operator/my_app/saved/searches/witness_object"
            ),
            "an_operator",
        )

    def test_the_segment_is_decoded(self):
        self.assertEqual(
            namespace_owner_from_id(
                "/servicesNS/an%20operator/my_app/saved/searches/witness_object"
            ),
            "an operator",
        )

    def test_absence_of_data_yields_none(self):
        """With no namespace, the command invents nothing: it does not have the
        datum."""
        for value in (
            None,
            "",
            "   ",
            "https://base.invalid:0/services/saved/searches/witness_object",
            "/servicesNS/an_operator/my_app/witness_object",   # path too short
        ):
            with self.subTest(value=value):
                self.assertIsNone(namespace_owner_from_id(value))

    def test_the_comparison_to_the_fixed_context_is_case_insensitive(self):
        for value in ("nobody", "NOBODY", " Nobody "):
            with self.subTest(value=value):
                self.assertTrue(is_fixed_context(value))
        for value in (None, "", "an_operator"):
            with self.subTest(value=value):
                self.assertFalse(is_fixed_context(value))

    def test_the_object_name_is_not_confused_with_the_owner(self):
        """The last segment is the name, the first is the owner. An `id` whose object
        name happened to be `nobody` must not pass for shared."""
        self.assertEqual(
            namespace_owner_from_id(
                "/servicesNS/an_operator/my_app/saved/searches/nobody"
            ),
            "an_operator",
        )


if __name__ == "__main__":
    unittest.main()
