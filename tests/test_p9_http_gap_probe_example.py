"""Tests for the targeted value-free P9 HTTP gap probe."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest import mock

from examples import p9_http_gap_probe as example

from tplink_deco_api import EndpointObservation, get_endpoint

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_http_gap_probe_reports_progress_and_retains_only_observations(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "p9-http-gap.json"
    client = mock.Mock()
    client.observe_endpoint_schema.side_effect = [
        EndpointObservation(
            name=name,
            status="supported",
            response_kind="object",
            elapsed_seconds=0.1,
            error_code=0,
            schema_paths=("$.status:string", "$:object"),
            schema_sha256="digest",
        )
        for name in example._TARGET_NAMES
    ]
    with (
        mock.patch.object(example, "_password", return_value="secret"),
        mock.patch.object(example, "DecoClient", return_value=client),
    ):
        example.main(["--host", "192.0.2.1", "--output", str(output)])

    assert client.observe_endpoint_schema.call_args_list == [
        mock.call(get_endpoint(name)) for name in example._TARGET_NAMES
    ]
    client.logout.assert_called_once_with()
    result = json.loads(output.read_text())
    assert result["selected_operations"] == list(example._TARGET_NAMES)
    assert len(result["observations"]) == 3
    assert result["sensitive_operations_included"] is False
    assert result["binary_operations_included"] is False
    assert result["mutation_invoked"] is False
    assert result["values_retained"] is False
    assert result["raw_values_emitted"] is False
    assert "private" not in output.read_text()
    captured = capsys.readouterr().out
    assert "[endpoint 1/3] admin.firmware.upgrade.read" in captured
    assert f"Value-free result: {output}" in captured
