import hashlib
from datetime import datetime
from pathlib import Path

from fim_agent.core.config import Config
from fim_agent.core.hasher import build_baseline, compute_file_hash
from fim_agent.core.storage import Storage


def test_compute_file_hash(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("hello", encoding="utf-8")

    expected = hashlib.sha256(b"hello").hexdigest()
    assert compute_file_hash(file_path) == expected


def test_storage_upsert_and_get(tmp_path):
    db_path = tmp_path / "db.sqlite3"
    storage = Storage(str(db_path))
    storage.init_schema()

    now = datetime.utcnow()
    storage.upsert_file("file1", "hash1", "create", now)
    record = storage.get_file("file1")
    assert record is not None
    assert record["hash"] == "hash1"

    storage.upsert_file("file1", "hash2", "modify", now)
    updated = storage.get_file("file1")
    assert updated is not None
    assert updated["hash"] == "hash2"
    assert updated["first_seen"] == record["first_seen"]
    assert updated["last_event_type"] == "modify"


def test_build_baseline(tmp_path):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    included_file = monitored_dir / "include.txt"
    included_file.write_text("data", encoding="utf-8")
    excluded_file = monitored_dir / "skip.log"
    excluded_file.write_text("skip", encoding="utf-8")

    config = Config(
        monitored_directories=[str(monitored_dir)],
        exclude_directories=[],
        exclude_extensions=[".log"],
        database_path=str(tmp_path / "db.sqlite3"),
        log_file="log",
        log_format="json",
    )
    storage = Storage(config.database_path)
    storage.init_schema()

    hashed = build_baseline([monitored_dir], storage, config)
    assert hashed == 1

    record = storage.get_file(str(included_file))
    assert record is not None
    assert record["hash"] == compute_file_hash(included_file)
    assert storage.get_file(str(excluded_file)) is None


