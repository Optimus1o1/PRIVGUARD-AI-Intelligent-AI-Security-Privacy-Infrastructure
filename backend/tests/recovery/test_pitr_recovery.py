"""Unit tests for Point-in-Time Recovery (PITR) WAL Replay Automation.
Verifies WAL segment discovery, sequential replay, LSN target bounds,
and failure behavior on invalid directories.
"""

from datetime import datetime, timezone
import pytest

from scripts.recovery.pitr_replay import replay_wal_archive


def test_nonexistent_wal_dir_raises(tmp_path):
    missing_dir = tmp_path / "nonexistent_wal"
    with pytest.raises(FileNotFoundError):
        replay_wal_archive(missing_dir)


def test_empty_wal_archive_handling(tmp_path):
    empty_dir = tmp_path / "empty_wal"
    empty_dir.mkdir()
    res = replay_wal_archive(empty_dir)
    assert res["status"] == "EMPTY_ARCHIVE"
    assert res["segments_replayed"] == 0


def test_sequential_wal_replay_to_completion(tmp_path):
    wal_dir = tmp_path / "wal"
    wal_dir.mkdir()

    # Create 3 synthetic 16MB WAL segment files
    for i in range(1, 4):
        seg_file = wal_dir / f"00000001000000000000000{i}"
        seg_file.write_bytes(b"\x00" * 1024)

    res = replay_wal_archive(wal_dir)
    assert res["status"] == "COMPLETED"
    assert res["segments_replayed"] == 3
    assert len(res["replayed_files"]) == 3
    assert res["reached_target"] is True


def test_wal_replay_stops_at_target_lsn(tmp_path):
    wal_dir = tmp_path / "wal"
    wal_dir.mkdir()

    for i in range(1, 6):
        seg_file = wal_dir / f"00000001000000000000000{i}"
        seg_file.write_bytes(b"\x00" * 1024)

    # Replay with target LSN that matches the 2nd segment
    target_lsn = "0/2000000"
    res = replay_wal_archive(wal_dir, target_lsn=target_lsn)
    assert res["status"] == "COMPLETED"
    assert res["segments_replayed"] == 2
    assert res["final_lsn"] >= target_lsn
    assert res["reached_target"] is True

