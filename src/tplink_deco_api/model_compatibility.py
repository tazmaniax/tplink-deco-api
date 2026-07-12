"""Bundled model-specific overlays for the generic Deco endpoint catalogue."""

from __future__ import annotations

from collections.abc import Mapping
from importlib import resources
from typing import TYPE_CHECKING, cast

from ._json import JsonObject, get_int, get_str, get_str_tuple, loads
from .endpoint_catalog import (
    CATALOG_VERSION,
    ENDPOINT_CATALOG,
    P9_MUTATION_CANDIDATES,
)
from .models import ModelCompatibilityProfile, OperationCompatibility

if TYPE_CHECKING:
    from .endpoint_spec import AuthenticationMode, EndpointSpec
    from .models.operation_compatibility import (
        Availability,
        EvidenceSource,
        MutationTestScope,
    )

_AVAILABILITIES: frozenset[str] = frozenset(
    {"supported", "rejected", "not_found", "transport_error", "invalid_response"}
)
_AUTHENTICATION_MODES: frozenset[str] = frozenset(
    {"encrypted", "plain", "multipart", "download", "bootstrap", "group_key", "token"}
)
_MUTATION_TEST_SCOPES: frozenset[str] = frozenset({"noop_only", "general"})


def _records(data: JsonObject, key: str) -> tuple[JsonObject, ...]:
    value = data.get(key)
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _availability(data: JsonObject) -> Availability:
    value = get_str(data, "availability")
    if value not in _AVAILABILITIES:
        raise ValueError(f"Failed to load model compatibility: invalid availability {value!r}")
    return cast("Availability", value)


def _optional_int(data: JsonObject, key: str) -> int | None:
    value = data.get(key)
    return get_int(data, key) if isinstance(value, int) and not isinstance(value, bool) else None


def _optional_bool(data: JsonObject, key: str) -> bool | None:
    value = data.get(key)
    return value if isinstance(value, bool) else None


def _transport_overrides(data: JsonObject) -> dict[str, AuthenticationMode]:
    value = data.get("transport_overrides")
    if not isinstance(value, Mapping):
        return {}
    overrides: dict[str, AuthenticationMode] = {}
    for name, authentication in value.items():
        if isinstance(authentication, str) and authentication in _AUTHENTICATION_MODES:
            overrides[name] = cast("AuthenticationMode", authentication)
    return overrides


def _mutation_observations() -> dict[str, JsonObject]:
    payload = (
        resources.files("tplink_deco_api.data")
        .joinpath("p9_mutation_compatibility.json")
        .read_text(encoding="utf-8")
    )
    data = loads(payload)
    if get_int(data, "schema_version") != 1:
        raise ValueError("Failed to load mutation compatibility: unsupported schema version")
    observations = {get_str(item, "name"): item for item in _records(data, "observations")}
    for observation in observations.values():
        if get_str(observation, "test_scope") not in _MUTATION_TEST_SCOPES:
            raise ValueError("Failed to load mutation compatibility: invalid test scope")
    return observations


def _bootstrap_observations() -> dict[str, JsonObject]:
    payload = (
        resources.files("tplink_deco_api.data")
        .joinpath("p9_bootstrap_compatibility.json")
        .read_text(encoding="utf-8")
    )
    data = loads(payload)
    if get_int(data, "schema_version") != 1:
        raise ValueError("Failed to load bootstrap compatibility: unsupported schema version")
    return {get_str(item, "name"): item for item in _records(data, "observations")}


def _binary_observations() -> dict[str, JsonObject]:
    payload = (
        resources.files("tplink_deco_api.data")
        .joinpath("p9_binary_compatibility.json")
        .read_text(encoding="utf-8")
    )
    data = loads(payload)
    if get_int(data, "schema_version") != 1:
        raise ValueError("Failed to load binary compatibility: unsupported schema version")
    return {get_str(item, "name"): item for item in _records(data, "observations")}


def _build_p9_profile() -> ModelCompatibilityProfile:
    payload = (
        resources.files("tplink_deco_api.data")
        .joinpath("p9_compatibility.json")
        .read_text(encoding="utf-8")
    )
    data = loads(payload)
    schema_version = get_int(data, "schema_version")
    if schema_version != 1:
        raise ValueError(
            f"Failed to load model compatibility: unsupported schema version {schema_version}"
        )
    if get_int(data, "catalog_version") != CATALOG_VERSION:
        raise ValueError("Failed to load model compatibility: catalog version does not match")

    full_observations = {
        get_str(item, "name"): item for item in _records(data, "full_manifest_observations")
    }
    live_observations = {
        get_str(item, "name"): item for item in _records(data, "live_asset_observations")
    }
    sensitive_observations = {
        get_str(item, "name"): item for item in _records(data, "sensitive_schema_observations")
    }
    asset_forms = frozenset(
        tuple(value.rsplit("/", 1)) for value in get_str_tuple(data, "asset_forms") if "/" in value
    )
    mutation_candidates = frozenset(endpoint.name for endpoint in P9_MUTATION_CANDIDATES)
    transport_overrides = _transport_overrides(data)
    mutation_observations = _mutation_observations()
    bootstrap_observations = _bootstrap_observations()
    binary_observations = _binary_observations()
    operations: list[OperationCompatibility] = []

    for endpoint in ENDPOINT_CATALOG:
        evidence: list[EvidenceSource] = ["catalog"]
        asset_present = (endpoint.path, endpoint.form) in asset_forms
        observation = full_observations.get(endpoint.name)
        if observation is not None:
            evidence.append("full_manifest")
        if asset_present:
            evidence.append("web_asset")
        live_observation = live_observations.get(endpoint.name)
        if live_observation is not None:
            observation = live_observation
            evidence.append("live_asset_probe")
        sensitive_observation = sensitive_observations.get(endpoint.name)
        if sensitive_observation is not None:
            observation = sensitive_observation
            evidence.append("sensitive_schema_probe")
        if endpoint.name in mutation_candidates:
            evidence.append("same_form_inference")
        bootstrap_observation = bootstrap_observations.get(endpoint.name)
        if bootstrap_observation is not None:
            evidence.append("bootstrap_probe")
            observation = bootstrap_observation
        binary_observation = binary_observations.get(endpoint.name)
        if binary_observation is not None:
            evidence.append("binary_digest_probe")
            observation = binary_observation
        mutation_observation = mutation_observations.get(endpoint.name)
        if mutation_observation is not None:
            evidence.append("mutation_probe")
            observation = mutation_observation

        operations.append(
            OperationCompatibility(
                name=endpoint.name,
                availability=_availability(observation) if observation is not None else "untested",
                evidence=tuple(evidence),
                returned_data=(
                    _optional_bool(observation, "returned_data")
                    if observation is not None
                    else None
                ),
                asset_present=asset_present,
                mutation_tested=mutation_observation is not None,
                mutation_test_scope=(
                    cast(
                        "MutationTestScope",
                        get_str(mutation_observation, "test_scope"),
                    )
                    if mutation_observation is not None
                    else "none"
                ),
                error_code=(
                    _optional_int(observation, "error_code") if observation is not None else None
                ),
                http_status=(
                    _optional_int(observation, "http_status") if observation is not None else None
                ),
                schema_paths=(
                    get_str_tuple(observation, "schema_paths") if observation is not None else ()
                ),
                schema_sha256=(
                    get_str(observation, "schema_sha256") if observation is not None else ""
                ),
                transport_override=transport_overrides.get(endpoint.name),
            )
        )

    return ModelCompatibilityProfile(
        model=get_str(data, "model"),
        hardware_versions=get_str_tuple(data, "hardware_versions"),
        firmware_version=get_str(data, "firmware_version"),
        system_mode=get_str(data, "system_mode"),
        observed_at=get_str(data, "observed_at"),
        catalog_version=CATALOG_VERSION,
        operations=tuple(operations),
    )


P9_COMPATIBILITY_PROFILE: ModelCompatibilityProfile = _build_p9_profile()
SENSITIVE_SCHEMA_ENDPOINTS: tuple[EndpointSpec, ...] = tuple(
    endpoint
    for endpoint in ENDPOINT_CATALOG
    if endpoint.safety == "read_only"
    and endpoint.sensitivity == "secret"
    and (endpoint.generic_call_supported or endpoint.bootstrap_call_supported)
)
P9_SENSITIVE_SCHEMA_ENDPOINTS: tuple[EndpointSpec, ...] = tuple(
    endpoint
    for endpoint in SENSITIVE_SCHEMA_ENDPOINTS
    if P9_COMPATIBILITY_PROFILE.get(endpoint.name).asset_present
)


def get_compatibility_profile(model: str) -> ModelCompatibilityProfile:
    """Return a bundled model overlay by case-insensitive model name."""
    if model.strip().upper() != "P9":
        raise KeyError(f"Unknown Deco model compatibility profile: {model}")
    return P9_COMPATIBILITY_PROFILE
