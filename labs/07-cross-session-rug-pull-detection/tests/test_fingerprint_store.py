"""Tests for fingerprint_store module."""

from pathlib import Path

import pytest

from detection.store.fingerprint_store import (
    FingerprintStore,
    compute_tool_hash,
)


@pytest.fixture
def store(tmp_path):
    """Create a FingerprintStore with a temp database."""
    db_path = tmp_path / "test_fingerprints.db"
    return FingerprintStore(db_path)


def test_compute_tool_hash():
    """Hash is deterministic and unique per input."""
    h1 = compute_tool_hash("tool1", "desc1", "{}")
    h2 = compute_tool_hash("tool1", "desc2", "{}")
    h3 = compute_tool_hash("tool2", "desc1", "{}")

    assert h1 != h2  # Different description → different hash
    assert h1 != h3  # Different name → different hash
    assert len(h1) == 64  # SHA-256 hex = 64 chars


def test_insert_and_query_fingerprint(store):
    """Insert a fingerprint and retrieve it."""
    store.insert_fingerprint(
        server_id="srv1",
        server_url="http://localhost",
        session_number=1,
        session_id="session_1",
        tool_name="calculate_discount",
        tool_hash="abc123",
        description="Test description",
        input_schema="{}",
    )

    fps = store.get_fingerprints_for_session("srv1", 1)
    assert len(fps) == 1
    assert fps[0].tool_name == "calculate_discount"
    assert fps[0].tool_hash == "abc123"


def test_establish_baseline(store):
    """Establish a baseline and retrieve it."""
    store.establish_baseline(
        server_id="srv1",
        tool_name="calculate_discount",
        tool_hash="baseline_hash",
        description="Baseline description",
        input_schema="{}",
    )

    baseline = store.get_baseline("srv1", "calculate_discount")
    assert baseline is not None
    assert baseline.baseline_hash == "baseline_hash"
    assert baseline.description == "Baseline description"


def test_baseline_not_overwritten(store):
    """Establishing a baseline twice does not overwrite."""
    store.establish_baseline(
        server_id="srv1",
        tool_name="calculate_discount",
        tool_hash="hash1",
        description="First",
        input_schema="{}",
    )
    store.establish_baseline(
        server_id="srv1",
        tool_name="calculate_discount",
        tool_hash="hash2",
        description="Second",
        input_schema="{}",
    )

    baseline = store.get_baseline("srv1", "calculate_discount")
    assert baseline.baseline_hash == "hash1"  # First value preserved


def test_reset_baselines(store):
    """Reset baselines removes them."""
    store.establish_baseline(
        server_id="srv1",
        tool_name="tool1",
        tool_hash="hash1",
        description="Desc",
        input_schema="{}",
    )
    store.reset_baselines("srv1")
    assert store.get_baseline("srv1", "tool1") is None


def test_multiple_tools_baseline(store):
    """Multiple tools can have independent baselines."""
    for tool_name in ["tool1", "tool2", "tool3"]:
        store.establish_baseline(
            server_id="srv1",
            tool_name=tool_name,
            tool_hash=f"hash_{tool_name}",
            description=f"Desc {tool_name}",
            input_schema="{}",
        )

    baselines = store.get_baseline_for_server("srv1")
    assert len(baselines) == 3
    names = {b.tool_name for b in baselines}
    assert names == {"tool1", "tool2", "tool3"}
