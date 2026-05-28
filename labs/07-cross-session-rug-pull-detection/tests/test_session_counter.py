"""Tests for session_counter module."""

import os
import tempfile
from pathlib import Path

import pytest

from server.session_counter import SessionCounter


@pytest.fixture
def counter(tmp_path):
    """Create a SessionCounter with a temp database."""
    db_path = tmp_path / "test_sessions.db"
    return SessionCounter(db_path)


def test_initial_count_is_zero(counter):
    """Session count starts at zero."""
    assert counter.get_session_count() == 0


def test_increment_session(counter):
    """Incrementing adds one session."""
    count = counter.increment_session()
    assert count == 1
    assert counter.get_session_count() == 1


def test_multiple_increments(counter):
    """Multiple increments produce sequential counts."""
    counts = [counter.increment_session() for _ in range(5)]
    assert counts == [1, 2, 3, 4, 5]
    assert counter.get_session_count() == 5


def test_reset(counter):
    """Reset clears all sessions."""
    for _ in range(3):
        counter.increment_session()
    assert counter.get_session_count() == 3

    counter.reset()
    assert counter.get_session_count() == 0


def test_is_poisoned_below_threshold(counter):
    """Sessions at or below threshold are not poisoned."""
    for i in range(5):
        counter.increment_session()
    assert counter.is_poisoned(5) is False


def test_is_poisoned_above_threshold(counter):
    """Sessions above threshold are poisoned."""
    for _ in range(5):
        counter.increment_session()
    assert counter.is_poisoned(5) is False

    counter.increment_session()
    assert counter.is_poisoned(5) is True


def test_persistence(tmp_path):
    """Counter persists across instances."""
    db_path = tmp_path / "persist.db"
    c1 = SessionCounter(db_path)
    c1.reset()
    for _ in range(3):
        c1.increment_session()
    del c1

    c2 = SessionCounter(db_path)
    assert c2.get_session_count() == 3
    c2.reset()
    os.remove(db_path)
