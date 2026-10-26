"""Validate generated SBOMs against the official schemas (CI only)."""
import json
import sys

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

cdx, spdx = sys.argv[1], sys.argv[2]
with open(cdx) as fh:
    doc = json.load(fh)
doc.pop("$schema", None)
err = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(doc))
if err:
    sys.exit(f"CycloneDX invalid: {err}")
msgs = validate_full_spdx_document(parse_file(spdx))
if msgs:
    for m in msgs[:20]:
        print(m.validation_message)
    sys.exit(f"SPDX invalid: {len(msgs)} problem(s)")
print(f"{cdx}: {len(doc['components'])} components valid; {spdx} valid")
