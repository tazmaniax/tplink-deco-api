"""Finite JSON shapes used by protocol-neutral response contracts."""

from __future__ import annotations

from typing import TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None
JsonScalarList: TypeAlias = list[JsonScalar]
JsonRecord: TypeAlias = dict[str, JsonScalar | JsonScalarList]
JsonRecordList: TypeAlias = list[JsonRecord]
JsonSection: TypeAlias = dict[
    str,
    JsonScalar | JsonScalarList | JsonRecord | JsonRecordList,
]
JsonSectionList: TypeAlias = list[JsonSection]
JsonDocument: TypeAlias = dict[
    str,
    JsonScalar | JsonScalarList | JsonRecord | JsonRecordList | JsonSection | JsonSectionList,
]
JsonDocumentList: TypeAlias = list[JsonDocument]
JsonData: TypeAlias = (
    JsonScalar
    | JsonScalarList
    | JsonRecord
    | JsonRecordList
    | JsonSection
    | JsonSectionList
    | JsonDocument
    | JsonDocumentList
)
ResponseDocument: TypeAlias = dict[str, JsonData]
