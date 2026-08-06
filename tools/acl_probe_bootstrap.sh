#!/bin/bash
# =============================================================================
# acl_probe_bootstrap.sh — amorcage de l'app jetable `acl_probe`
# -----------------------------------------------------------------------------
# Cree, sur une instance Splunk Enterprise standalone, une app de test portant
# un objet de chaque grande famille d'objets de connaissance, dans les trois
# portees de partage (user / app / global), avec et sans permissions explicites.
#
# Volet 1 (ce script) : objets declares par fichiers de configuration.
# Volet 2 (acl_probe_bootstrap_rest.py) : objets prives (sharing=user) et objets
#          a nom special (barre oblique, espace, accent, pourcent), crees par
#          l'API REST car leur namespace ou leur nom ne se declare pas en .conf.
#
# Idempotent : re-executable sans effet de bord (ecriture par template, jamais
# d'append). Ne contient AUCUN secret. Identifiants volontairement generiques.
#
# Usage (en root, sur l'instance) :  bash acl_probe_bootstrap.sh
# Suppression :                      bash acl_probe_bootstrap.sh --remove
# =============================================================================
set -euo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
APP="acl_probe"
APPDIR="$SPLUNK_HOME/etc/apps/$APP"

if [ "${1:-}" = "--remove" ]; then
  rm -rf "$APPDIR"
  rm -rf "$SPLUNK_HOME"/etc/users/*/"$APP"
  echo "removed $APPDIR (+ namespaces utilisateurs) ; redemarrer splunkd pour finaliser"
  exit 0
fi

mkdir -p "$APPDIR/default/data/ui/views" \
         "$APPDIR/default/data/ui/nav" \
         "$APPDIR/default/data/ui/panels" \
         "$APPDIR/default/data/models" \
         "$APPDIR/metadata" \
         "$APPDIR/lookups"

cat > "$APPDIR/default/app.conf" <<'EOF'
[install]
state = enabled
is_configured = 1

[ui]
is_visible = 1
label = ACL Probe

[package]
id = acl_probe

[launcher]
author = acl-probe
description = App jetable de test des ACL (objets de connaissance temoins)
version = 1.0.0
EOF

cat > "$APPDIR/default/authorize.conf" <<'EOF'
# Capability declaree par l'app : sert a mesurer sa remontee dans
# GET /services/authentication/current-context une fois attribuee a un role.
[capability::probe_capability]
EOF

cat > "$APPDIR/default/savedsearches.conf" <<'EOF'
[probe_search_app]
search = index=_internal | head 1

[probe_search_global]
search = index=_internal | head 2

[probe_search_noperms]
search = index=_internal | head 3

[probe_alert_app]
search = index=_internal | head 4
enableSched = 1
cron_schedule = 0 6 * * *
alert_type = number of events
alert_comparator = greater than
alert_threshold = 0
counttype = number of events
relation = greater than
quantity = 0
EOF

cat > "$APPDIR/default/eventtypes.conf" <<'EOF'
[probe_eventtype_app]
search = index=_internal sourcetype=splunkd
EOF

cat > "$APPDIR/default/tags.conf" <<'EOF'
[eventtype=probe_eventtype_app]
probe_tag_evt = enabled

[probe_field=probe_value]
probe_tag_fv = enabled
EOF

cat > "$APPDIR/default/macros.conf" <<'EOF'
[probe_macro_app]
definition = index=_internal

[probe_macro_arg(1)]
args = n
definition = index=_internal | head $n$
EOF

cat > "$APPDIR/default/transforms.conf" <<'EOF'
[probe_lookup_def]
filename = probe_lookup.csv

[probe_transform_extract]
REGEX = probe_key=(?<probe_key>\w+)
EOF

cat > "$APPDIR/default/props.conf" <<'EOF'
[probe_sourcetype]
EXTRACT-probe_extract = probe_field=(?<probe_field>\w+)
REPORT-probe_report = probe_transform_extract
LOOKUP-probe_auto = probe_lookup_def probe_key OUTPUT probe_value
FIELDALIAS-probe_alias = probe_field AS probe_field_alias
EVAL-probe_eval = probe_eval_field=1
EOF

cat > "$APPDIR/default/times.conf" <<'EOF'
[probe_time_range]
label = Probe range
earliest_time = -7d@d
latest_time = now
order = 1
is_sub_menu = 0
EOF

cat > "$APPDIR/default/collections.conf" <<'EOF'
[probe_collection]
enforceTypes = false
EOF

cat > "$APPDIR/default/workflow_actions.conf" <<'EOF'
[probe_workflow]
type = link
label = Probe action
display_location = event_menu
link.uri = https://example.invalid/probe
link.method = get
EOF

cat > "$APPDIR/default/viewstates.conf" <<'EOF'
[probe_view_app:probe_viewstate]
EOF

cat > "$APPDIR/default/data/ui/views/probe_view_app.xml" <<'EOF'
<dashboard version="1.1">
  <label>Probe view app</label>
  <row><panel><html><p>probe</p></html></panel></row>
</dashboard>
EOF

cat > "$APPDIR/default/data/ui/views/probe_view_global.xml" <<'EOF'
<dashboard version="1.1">
  <label>Probe view global</label>
  <row><panel><html><p>probe</p></html></panel></row>
</dashboard>
EOF

cat > "$APPDIR/default/data/ui/nav/default.xml" <<'EOF'
<nav>
  <view name="probe_view_app" default="true"/>
  <view name="probe_view_global"/>
</nav>
EOF

cat > "$APPDIR/default/data/ui/panels/probe_panel.xml" <<'EOF'
<panel>
  <title>Probe panel</title>
  <html><p>probe</p></html>
</panel>
EOF

cat > "$APPDIR/default/data/models/probe_datamodel.json" <<'EOF'
{
  "modelName": "probe_datamodel",
  "displayName": "Probe datamodel",
  "description": "",
  "objectSummary": {"Event-Based": 1, "Transaction-Based": 0, "Search-Based": 0},
  "objects": [
    {
      "objectName": "probe_root",
      "displayName": "Probe root",
      "parentName": "BaseEvent",
      "comment": "",
      "fields": [
        {"fieldName": "host", "owner": "BaseEvent", "type": "string",
         "fieldSearch": "", "required": false, "multivalue": false,
         "hidden": false, "editable": false, "displayName": "host", "comment": ""}
      ],
      "constraints": [
        {"search": "index=_internal", "owner": "probe_root"}
      ],
      "calculations": [],
      "lineage": "probe_root"
    }
  ],
  "objectNameList": ["probe_root"]
}
EOF

cat > "$APPDIR/lookups/probe_lookup.csv" <<'EOF'
probe_key,probe_value
alpha,1
beta,2
EOF

# metadata : pas de stanza [] portant `access`, afin que la majorite des objets
# reste SANS permissions explicites (cas de test du §10.1 du cahier des charges).
cat > "$APPDIR/metadata/default.meta" <<'EOF'
[]
export = none

[savedsearches/probe_search_global]
export = system
access = read : [ * ], write : [ admin, power ]

[savedsearches/probe_search_noperms]
export = system

[views/probe_view_global]
export = system

[eventtypes/probe_eventtype_app]
access = read : [ * ], write : [ admin ]
EOF

chown -R splunk:splunk "$APPDIR"
echo "OK: $APPDIR ecrit"
