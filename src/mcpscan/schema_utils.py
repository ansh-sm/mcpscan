"""Recursive JSON Schema traversal engine for deep property inspection.

Walks arbitrarily nested JSON Schema structures including:
- ``properties`` (object schemas)
- ``items`` (array element schemas)
- ``allOf`` / ``anyOf`` / ``oneOf`` (composition keywords)
- ``$defs`` / ``definitions`` with ``$ref`` resolution (local-only, cycle-safe)
- ``additionalProperties`` (when schema-valued)
- ``prefixItems`` (tuple validation)

This prevents rules from being fooled by schemas that hide dangerous
parameters inside nested objects, arrays, or composition branches.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SchemaNode:
    """A single property encountered during recursive schema traversal."""

    name: str
    schema: dict[str, Any]
    json_path: str
    depth: int


def _resolve_ref(
    ref: str,
    root_schema: dict[str, Any],
) -> dict[str, Any] | None:
    """Resolve a *local-only* ``$ref`` pointer (e.g. ``#/$defs/Foo``).

    Remote ``$ref`` values are deliberately ignored — we only analyse
    the schema as declared in the server manifest.
    """
    if not ref.startswith("#/"):
        return None

    segments = ref[2:].split("/")
    node: Any = root_schema
    for segment in segments:
        # JSON Pointer escapes
        segment = segment.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            node = node.get(segment)
        else:
            return None
        if node is None:
            return None

    return node if isinstance(node, dict) else None


def walk_schema(
    schema: dict[str, Any],
    *,
    root_schema: dict[str, Any] | None = None,
    _path_prefix: str = "",
    _depth: int = 0,
    _max_depth: int = 12,
    _seen_refs: set[str] | None = None,
) -> Iterator[SchemaNode]:
    """Yield every leaf property reachable from *schema*.

    Parameters
    ----------
    schema:
        The JSON Schema (or sub-schema) to walk.
    root_schema:
        The top-level schema for ``$ref`` resolution. Defaults to *schema*.
    _path_prefix:
        JSON-path prefix for the current position.
    _depth:
        Current recursion depth (guarded by *_max_depth*).
    _max_depth:
        Safety limit to avoid unbounded recursion on pathological schemas.
    _seen_refs:
        Set of already-visited ``$ref`` pointers for cycle detection.
    """
    if _depth > _max_depth:
        return

    if root_schema is None:
        root_schema = schema

    if _seen_refs is None:
        _seen_refs = set()

    # --- $ref resolution (cycle-safe) ---
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in _seen_refs:
            return  # cycle
        _seen_refs = _seen_refs | {ref}
        resolved = _resolve_ref(ref, root_schema)
        if resolved is not None:
            yield from walk_schema(
                resolved,
                root_schema=root_schema,
                _path_prefix=_path_prefix,
                _depth=_depth,
                _max_depth=_max_depth,
                _seen_refs=_seen_refs,
            )
        return

    # --- properties (object type) ---
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for prop_name, prop_schema in properties.items():
            if not isinstance(prop_schema, dict):
                continue
            child_path = f"{_path_prefix}.{prop_name}" if _path_prefix else prop_name
            yield SchemaNode(
                name=prop_name,
                schema=prop_schema,
                json_path=child_path,
                depth=_depth,
            )
            # Recurse into the property itself (it may be an object/array/composition)
            yield from walk_schema(
                prop_schema,
                root_schema=root_schema,
                _path_prefix=child_path,
                _depth=_depth + 1,
                _max_depth=_max_depth,
                _seen_refs=_seen_refs,
            )

    # --- items (array element schema) ---
    items = schema.get("items")
    if isinstance(items, dict):
        items_path = f"{_path_prefix}.items" if _path_prefix else "items"
        yield from walk_schema(
            items,
            root_schema=root_schema,
            _path_prefix=items_path,
            _depth=_depth + 1,
            _max_depth=_max_depth,
            _seen_refs=_seen_refs,
        )

    # --- prefixItems (tuple validation) ---
    prefix_items = schema.get("prefixItems")
    if isinstance(prefix_items, list):
        for idx, item_schema in enumerate(prefix_items):
            if isinstance(item_schema, dict):
                item_path = f"{_path_prefix}.prefixItems[{idx}]" if _path_prefix else f"prefixItems[{idx}]"
                yield from walk_schema(
                    item_schema,
                    root_schema=root_schema,
                    _path_prefix=item_path,
                    _depth=_depth + 1,
                    _max_depth=_max_depth,
                    _seen_refs=_seen_refs,
                )

    # --- additionalProperties (when schema, not boolean) ---
    additional = schema.get("additionalProperties")
    if isinstance(additional, dict):
        add_path = f"{_path_prefix}.additionalProperties" if _path_prefix else "additionalProperties"
        yield from walk_schema(
            additional,
            root_schema=root_schema,
            _path_prefix=add_path,
            _depth=_depth + 1,
            _max_depth=_max_depth,
            _seen_refs=_seen_refs,
        )

    # --- composition keywords ---
    for keyword in ("allOf", "anyOf", "oneOf"):
        branches = schema.get(keyword)
        if isinstance(branches, list):
            for i, branch in enumerate(branches):
                if isinstance(branch, dict):
                    branch_path = f"{_path_prefix}.{keyword}[{i}]" if _path_prefix else f"{keyword}[{i}]"
                    yield from walk_schema(
                        branch,
                        root_schema=root_schema,
                        _path_prefix=branch_path,
                        _depth=_depth + 1,
                        _max_depth=_max_depth,
                        _seen_refs=_seen_refs,
                    )
