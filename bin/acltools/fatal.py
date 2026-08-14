"""The fatal diagnostic - one message, one shape, one place (v4.8 section 13.2).

**Why this module exists, and it is not tidiness.** Measured on 2026-08-13 (friction
#435): on a fresh installation with no `local/editacl.conf`, that is on a platform with a
self-signed certificate and `verify_ssl` at its default, `editacl` failed **saying why** -
cause, remedy and the certificate detail - while `appaclinventory` failed **mute**:
`isFailed=True`, and for the whole of its diagnosis *"External search command exited
unexpectedly with non-zero error code 1"*. That sentence is what splunkd writes in the
**absence** of any message from the command; reading it as a diagnosis is taking silence
for an answer.

**The arrival property PA** (section 13.2) is what this module serves, and it is stated on
the **job**, not on the code:

    1. the job is failed - `isFailed=True`;
    2. the messages of the job carry **at least one message emitted by the command**, whose
       text names **the cause** of the stop **and the remedy**;
    3. that message carries the prefix of the command.

This module owns points 2 and 3's payload: **one function** builds the text for both
commands, so that a fatal error can neither lose its remedy nor grow a second wording. The
adapters own the route the message takes, which is where the two commands genuinely
differ - and where the defect was.

**Cause and remedy are two segments, and both are required.** A cause with no remedy tells
the operator that he is stuck, which he already knew. The separator is published so a test
can split on it rather than parse prose.
"""

from .errors import (
    FatalCapabilityError,
    FatalConfigError,
    FatalError,
    FatalFamilyTableError,
    FatalJournalError,
    FatalMappingError,
    FatalProvenanceRootError,
    FatalSessionError,
)

#: What separates the cause segment from the remedy segment inside the message.
#:
#: Published rather than inlined: the test of section 14.2 splits on it to check that
#: **both** segments are non-empty, and a separator written twice would be a separator
#: nobody can rely on.
REMEDY_SEPARATOR = " -- remedy: "

#: Remedy per fatal error class of section 13.1, and the mapping is **total**: a test
#: derives the class list from the core - `FatalError.__subclasses__()` - and fails on the
#: first class this table does not answer for. A fatal error added tomorrow without a
#: remedy therefore fails the suite instead of reaching an operator.
#:
#: Each remedy names **an act**, not a state of affairs. "The capability is missing" is a
#: cause; "grant it to the role, or run as an account that holds it" is a remedy.
FATAL_REMEDIES = {
    FatalSessionError: (
        "check that splunkd answers on its management port, that the session is still "
        "valid, and - on a platform with a self-signed certificate - set verify_ssl = "
        "false under [editacl] in local/editacl.conf of this app, or install the "
        "platform CA in $SPLUNK_HOME/etc/auth/cacert.pem."
    ),
    FatalCapabilityError: (
        "grant the capability the message names to one of your roles, or run the search "
        "as an account that already holds it; if the search is a real-time one, run it "
        "over a bounded time range instead."
    ),
    FatalConfigError: (
        "correct the parameter the message names and run the search again; the accepted "
        "values are in the search assistant and in the README."
    ),
    FatalMappingError: (
        "restore bin/acl_endpoint_map.json, or correct the override "
        "lookups/acl_endpoint_map_override.csv - one line per object type, columns "
        "eai_type and handler_path."
    ),
    FatalFamilyTableError: (
        "restore bin/app_acl_family_map.json, or correct the override "
        "lookups/app_acl_family_map_override.csv - one line per family, columns family "
        "and handler_path."
    ),
    FatalJournalError: (
        "make $SPLUNK_HOME/var/log/splunk writable by the splunk account, or run with "
        "journal=false - which trades the ability to roll the run back."
    ),
    FatalProvenanceRootError: (
        "set SPLUNK_HOME to the instance this search runs on, and check that "
        "$SPLUNK_HOME/etc/apps exists and is the tree splunkd serves; the two routes of "
        "section 6.2 must agree."
    ),
}

#: Remedy used when a fatal error carries a class this table does not know.
#:
#: **It exists so the message is never remedy-less**, not to excuse an omission: the test
#: above fails on an unmapped class, so this text is unreachable through the declared
#: taxonomy. It covers what no test can - a fatal error raised through a class defined
#: outside this package.
FALLBACK_REMEDY = (
    "read the cause above, correct it, and run the search again; if the cause names no "
    "act you can take, report it with the search id."
)


def fatal_error_classes():
    """The fatal error classes, **derived from the core** and never listed by hand.

    Walks the subclasses of `FatalError` transitively: the taxonomy of section 13.1 is
    the class hierarchy, so a class added there is covered here the moment it exists.
    """
    found, queue = [], [FatalError]
    while queue:
        current = queue.pop()
        for subclass in current.__subclasses__():
            if subclass not in found:
                found.append(subclass)
                queue.append(subclass)
    return tuple(found)


def remedy_for(error):
    """The remedy segment for this error, walking the class hierarchy upwards.

    A subclass added to an existing family inherits the remedy of its parent rather than
    falling through to the generic text - which is the behaviour that keeps the message
    useful when the taxonomy grows.
    """
    for klass in type(error).__mro__:
        if klass in FATAL_REMEDIES:
            return FATAL_REMEDIES[klass]
    return FALLBACK_REMEDY


def fatal_diagnostic(error):
    """**The** text of a fatal error, for both commands (section 13.2).

    `<cause> -- remedy: <act to take>`. The cause is the message the raising site wrote,
    because that site is the only one that knows what it just observed; the remedy comes
    from the class, because that is what is stable across raising sites.

    Total by construction: an error with an empty message still yields a named cause, and
    every error yields a remedy. A diagnostic that can come out empty is a diagnostic that
    will come out empty on the day it matters.
    """
    cause = str(error or "").strip()
    if not cause:
        cause = "%s (no detail given)" % type(error).__name__
    return "%s%s%s" % (cause, REMEDY_SEPARATOR, remedy_for(error))
