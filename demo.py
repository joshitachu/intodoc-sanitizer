#!/usr/bin/env python3
"""End-to-end demo of the sanitization pipeline.

Run:  python demo.py

Shows all four stages on a synthetic Talend-style job. Every secret below is
fabricated -- this file contains no real credential and no client data.

    raw text  --(1)-->  filtered text  --parse-->  models
              --(2)-->  structurally redacted models
              --(3)-->  verification gate (fail closed)
              --(4)-->  distilled, LLM-sized chunks
"""

from __future__ import annotations

import json

from intodoc.config import RedactionLevel
from intodoc.models import (
    Component,
    ComponentParam,
    ContextGroup,
    ContextVariable,
    MetadataConnection,
    ParsedJob,
    ScanResult,
)
from intodoc.platforms.talend.distiller import TalendDistiller
from intodoc.scanner.credential_filter import CredentialFilter
from intodoc.scanner.post_filter import filter_scan_result
from intodoc.scanner.redaction_verifier import verify_scan_result

RAW_XML = """<?xml version="1.0" encoding="UTF-8"?>
<talendfile:ProcessType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                        xmlns:talendfile="platform:/resource/model/talendfile.ecore">
  <node componentName="tMSSqlInput" posX="128" posY="96" offsetLabelX="0">
    <elementParameter field="TEXT"     name="HOST"        value="sqlprod01.acme-internal.nl"/>
    <elementParameter field="TEXT"     name="PORT"        value="1433"/>
    <elementParameter field="PASSWORD" name="id_Password" value="Sup3rS3cret!"/>
    <elementParameter field="TEXT"     name="QUERY"
        value="SELECT OrderId, CustomerRef FROM dbo.Orders WHERE Status = 'NEW'"/>
    <elementParameter field="CHECK"    name="DIE_ON_ERROR" value="true"/>
    <elementParameter field="CHECK"    name="TSTATCATCHER_STATS" value="false"/>
    <elementParameter field="TEXT"     name="ENCODING"    value="UTF-8"/>
    <elementParameter field="TEXT"     name="HINT"        value="Reads new orders"/>
  </node>
  <node componentName="tRESTClient" posX="380" posY="96">
    <elementParameter field="TEXT" name="URL"
        value="https://api.partner.example.com/v2/orders?apikey=ab12cd34ef56gh78"/>
    <elementParameter field="TEXT" name="AUTH_HEADER"
        value="Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"/>
    <elementParameter field="TEXT" name="KEYSTORE" value="/opt/talend/certs/client.pem"/>
  </node>
</talendfile:ProcessType>
"""


def rule(title: str) -> None:
    print(f"\n{'=' * 78}\n  {title}\n{'=' * 78}")


def main() -> None:
    cred_filter = CredentialFilter(level=RedactionLevel.STANDARD)

    # ── Layer 1: raw text, before any parsing ────────────────────────────
    rule("LAYER 1 -- text-level filter (runs BEFORE the XML parser)")
    filtered = cred_filter.filter_text(RAW_XML, filename="order_load_0.1.item")
    print(filtered)
    print("Note: the xmlns URIs survived verbatim (structure, not data);")
    print("      every endpoint, token and credential path did not.")

    # ── Parse (stand-in) ─────────────────────────────────────────────────
    # A real scan parses `filtered` into these models. Here they are built by
    # hand, deliberately carrying a value Layer 1 alone would not have caught:
    # a context variable whose NAME says "password" but whose value is plain.
    scan = ScanResult(
        platform="talend",
        repo_root="/demo",
        jobs=[
            ParsedJob(
                name="OrderLoad",
                path="process/OrderLoad_0.1.item",
                group="Orders",
                components=[
                    Component(
                        unique_name="tMSSqlInput_1",
                        component_type="tMSSqlInput",
                        params=[
                            ComponentParam(name="HOST", value="sqlprod01.acme-internal.nl", field_type="TEXT"),
                            ComponentParam(name="PORT", value="1433", field_type="TEXT"),
                            ComponentParam(name="QUERY", field_type="MEMO",
                                           value="SELECT OrderId FROM dbo.Orders"),
                            ComponentParam(name="DIE_ON_ERROR", value="true", field_type="CHECK"),
                            ComponentParam(name="TSTATCATCHER_STATS", value="false", field_type="CHECK"),
                            ComponentParam(name="ENCODING", value="UTF-8", field_type="TEXT"),
                            ComponentParam(name="HINT", value="Reads new orders", field_type="TEXT"),
                            ComponentParam(name="posX", value="128", field_type="TEXT"),
                        ],
                    ),
                    Component(
                        unique_name="tRunJob_1",
                        component_type="tRunJob",
                        params=[
                            ComponentParam(
                                name="CONTEXTPARAMS", value="", field_type="TABLE",
                                # The sensitivity is stated by the row's NAME cell,
                                # not by the parameter name -- see post_filter.
                                rows=[{
                                    "PARAM_NAME_COLUMN": "TargetDbPassword",
                                    "PARAM_VALUE_COLUMN": "hunter2",
                                }],
                            ),
                        ],
                    ),
                ],
                context_groups=[
                    ContextGroup(
                        name="Default",
                        variables=[
                            ContextVariable(name="OrderApiBaseUrl", type="String",
                                            values={"PROD": "https://api.partner.example.com/v2"}),
                            # camelCase + no id_Password type: only the token-aware
                            # name matcher catches this one.
                            ContextVariable(name="MaximoPassword", type="String",
                                            values={"PROD": "pl41nt3xt", "ACC": "pl41nt3xt"}),
                            ContextVariable(name="BatchSize", type="Integer",
                                            values={"PROD": "500", "ACC": "500"}),
                        ],
                    ),
                ],
            ),
        ],
        metadata_connections=[
            MetadataConnection(xmi_id="_conn1", name="OrdersDb", connection_type="MSSQL",
                               host="sqlprod01.acme-internal.nl", port="1433", database="ORDERS"),
        ],
    )

    # ── Layer 2: structural redaction on the parsed models ───────────────
    rule("LAYER 2 -- structural filter (semantics, not patterns)")
    before = scan.model_dump_json()
    filter_scan_result(scan, cred_filter)
    job = scan.jobs[0]
    print("context variables after Layer 2:")
    for var in job.context_groups[0].variables:
        print(f"  {var.name:<18} {var.values}")
    print("\ntRunJob CONTEXTPARAMS row after Layer 2:")
    print(f"  {job.components[1].params[0].rows[0]}")
    print(f"\nmetadata connection host: {scan.metadata_connections[0].host}")
    print("captured descriptor      :",
          scan.metadata_connections[0].host_redaction.model_dump(exclude_none=True)
          if scan.metadata_connections[0].host_redaction else None)
    print("  (a bare host string can only prove host_present -- nothing else")
    print("   is determinable from it, so nothing else is claimed)")

    api_var = job.context_groups[0].variables[0]
    print(f"\n{api_var.name} = {api_var.values}")
    print("captured descriptor      :",
          {env: d.model_dump(exclude_none=True)
           for env, d in api_var.redaction_descriptors.items()})
    print("\nmask-and-CAPTURE: the value is gone, but scheme/category/tls/auth")
    print("survive -- enough to document 'an unauthenticated HTTPS REST")
    print("endpoint' instead of a bare [URL_REDACTED].")

    # ── Layer 3: verification gate ───────────────────────────────────────
    rule("LAYER 3 -- verification gate (independent, fails the scan closed)")
    report = verify_scan_result(scan, cred_filter)
    print(json.dumps(report, indent=2)[:1500])
    print("\npassed =", report["passed"], "-- on False, no scan output is written at all.")

    # ── Audit trail ──────────────────────────────────────────────────────
    rule("AUDIT TRAIL -- counts and SHA-256 prefixes, never raw values")
    print(json.dumps(cred_filter.get_audit_report()["summary"], indent=2))

    # ── Layer 4: noise distillation ──────────────────────────────────────
    rule("DISTILLER -- strip UI noise and boilerplate, then chunk")
    params_before = [p.name for p in scan.jobs[0].components[0].params]
    chunks = TalendDistiller().distill(scan)
    params_after = [p.name for p in chunks[0].jobs[0].components[0].params]
    print(f"tMSSqlInput_1 params before: {params_before}")
    print(f"tMSSqlInput_1 params after : {params_after}")
    print(f"\nbytes before distill: {len(before):,}")
    print(f"bytes after  distill: {len(chunks[0].model_dump_json()):,}")
    print(f"chunks: {[c.chunk_id for c in chunks]}")


if __name__ == "__main__":
    main()
