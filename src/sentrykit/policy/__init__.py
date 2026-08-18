"""The shipped Cedar policy pack, and the loader that makes it an ordinary policy source.

Re-exported from :mod:`sentrykit.policy.loader` so the pack is addressable as
``sentrykit.policy`` — the pack files themselves live under ``sentrykit/policy/pack/`` and are
read as data, never imported.
"""

from __future__ import annotations

from sentrykit.policy.loader import (
    PACK_NAME,
    PATTERNS,
    SCHEMA_FILE,
    TEMPLATE_SUFFIX,
    LinkedPolicySource,
    PackPattern,
    PackPolicySource,
    TemplateLink,
    link_template,
    load_pack,
    pack_root,
    pack_schema,
    pack_template,
)

__all__ = [
    "PACK_NAME",
    "PATTERNS",
    "SCHEMA_FILE",
    "TEMPLATE_SUFFIX",
    "LinkedPolicySource",
    "PackPattern",
    "PackPolicySource",
    "TemplateLink",
    "link_template",
    "load_pack",
    "pack_root",
    "pack_schema",
    "pack_template",
]
