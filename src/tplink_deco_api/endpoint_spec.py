"""Machine-readable metadata for one Deco firmware operation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, TypeAlias

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ._json import JsonObject, JsonValue

AuthenticationMode: TypeAlias = Literal[
    "encrypted",
    "plain",
    "multipart",
    "download",
    "bootstrap",
    "group_key",
    "token",
]
ResponseKind: TypeAlias = Literal["object", "list", "value", "binary"]
SafetyLevel: TypeAlias = Literal["read_only", "mutation", "destructive", "internal"]
SensitivityLevel: TypeAlias = Literal["normal", "private", "secret"]
ContractSource: TypeAlias = Literal["none", "documented", "firmware_asset", "observed"]


@dataclass(frozen=True)
class EndpointSpec:
    """Describe how to call and safely expose one endpoint operation."""

    path: str
    form: str
    operation: str
    authentication: AuthenticationMode = "encrypted"
    response_kind: ResponseKind = "object"
    safety: SafetyLevel = "read_only"
    sensitivity: SensitivityLevel = "normal"
    default_params: JsonObject | None = None
    documentation: str = "docs/endpoints/README.md"
    media_type: str = "application/json"
    required_params: tuple[str, ...] = ()
    optional_params: tuple[str, ...] = ()
    contract_source: ContractSource = "none"
    form_selector: bool = True

    @property
    def name(self) -> str:
        """Return a stable dotted identifier suitable for tools and manifests."""
        path = self.path.strip("/").replace("/", ".").replace("-", "_")
        form = self.form.replace("-", "_")
        operation = self.operation.replace("-", "_")
        return f"{path}.{form}.{operation}"

    @property
    def idempotent(self) -> bool:
        """Return whether automatic repetition is safe by classification."""
        return self.safety == "read_only"

    @property
    def generic_call_supported(self) -> bool:
        """Return whether ``DecoClient.call`` supports this transport and response."""
        return self.authentication in {"encrypted", "plain"} and self.response_kind != "binary"

    @property
    def binary_call_supported(self) -> bool:
        """Return whether ``DecoClient.call_binary`` supports this operation."""
        return self.response_kind == "binary" and (
            self.authentication in {"download", "encrypted"}
            or (
                self.authentication == "multipart"
                and self.path == "admin/firmware"
                and self.form == "config_multipart"
                and self.operation == "backup"
            )
        )

    @property
    def bootstrap_call_supported(self) -> bool:
        """Return whether ``DecoClient.call_bootstrap`` supports this read."""
        return (
            self.authentication == "bootstrap"
            and self.path == "login"
            and self.operation == "read"
            and self.response_kind != "binary"
        )

    @property
    def impact(self) -> str:
        """Return a concise effect description for agent decision-making."""
        impacts = {
            "read_only": "retrieves state without intended mutation",
            "mutation": "changes configuration or runtime state",
            "destructive": "can interrupt service, remove data, reset, or upgrade devices",
            "internal": "invokes firmware-internal coordination or diagnostic behavior",
        }
        return impacts[self.safety]

    def request_data(
        self,
        params: Mapping[str, JsonValue] | None = None,
    ) -> dict[str, JsonValue]:
        """Build the logical request body using explicit or default parameters."""
        selected_params = params if params is not None else self.default_params
        self.validate_params(selected_params)
        data: dict[str, JsonValue] = {"operation": self.operation}
        if selected_params is not None:
            data["params"] = selected_params
        return data

    def missing_params(
        self,
        params: Mapping[str, JsonValue] | None = None,
    ) -> tuple[str, ...]:
        """Return documented required parameter names absent from a request."""
        selected_params = params if params is not None else self.default_params
        if selected_params is None:
            return self.required_params
        return tuple(name for name in self.required_params if name not in selected_params)

    def validate_params(
        self,
        params: Mapping[str, JsonValue] | None = None,
    ) -> None:
        """Reject a request missing documented required parameters."""
        missing = self.missing_params(params)
        if missing:
            joined = ", ".join(missing)
            raise ValueError(f"Failed to call {self.name}: missing required params: {joined}")

    def to_dict(self) -> dict[str, JsonValue]:
        """Return JSON-compatible metadata for discovery and MCP schemas."""
        return {
            "name": self.name,
            "path": self.path,
            "form": self.form,
            "operation": self.operation,
            "authentication": self.authentication,
            "response_kind": self.response_kind,
            "safety": self.safety,
            "sensitivity": self.sensitivity,
            "default_params": self.default_params,
            "documentation": self.documentation,
            "media_type": self.media_type,
            "required_params": list(self.required_params),
            "optional_params": list(self.optional_params),
            "contract_source": self.contract_source,
            "form_selector": self.form_selector,
            "idempotent": self.idempotent,
            "generic_call_supported": self.generic_call_supported,
            "binary_call_supported": self.binary_call_supported,
            "bootstrap_call_supported": self.bootstrap_call_supported,
            "impact": self.impact,
        }
