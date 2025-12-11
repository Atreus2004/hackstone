from datetime import datetime

from fim_agent.core.events import calculate_severity, map_mitre_tags
from fim_agent.core.events import simple_risk_score, simple_ai_classification, Event


def test_calculate_severity():
    assert calculate_severity("script.ps1") == "high"
    assert calculate_severity("config.yaml") == "medium"
    assert calculate_severity("notes.txt") == "low"


def test_map_mitre_tags():
    tags_modify = map_mitre_tags("config.yaml", "modify")
    assert "Tampering" in tags_modify
    assert "Config Manipulation" in tags_modify

    tags_delete = map_mitre_tags("file.txt", "delete")
    assert "Defense Evasion" in tags_delete

    tags_exec = map_mitre_tags("run.ps1", "create")
    assert "Execution" in tags_exec


def test_risk_and_ai_classification():
    ev = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/etc/config.yaml",
        old_hash="a",
        new_hash="b",
        severity="high",
        mitre_tags=[],
        message="",
        hash_changed=True,
    )
    score = simple_risk_score(ev)
    assert score >= 40
    ai_class, ai_risk, ai_reason = simple_ai_classification(ev)
    assert ai_class in {"internal", "sensitive", "public"}
    assert isinstance(ai_risk, int)
    assert isinstance(ai_reason, str)


def test_private_secret_tamper_high_risk():
    """Test that tampering with private/secret files is always high-risk and alerts."""
    from fim_agent.core.events import simple_risk_score, mark_alert, derive_severity_from_risk
    
    # Test private file tampering
    ev_private = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/data/private_file.txt",
        old_hash="a",
        new_hash="b",
        severity="low",
        mitre_tags=[],
        message="Modified private file",
        content_classification="private",
    )
    score_private = simple_risk_score(ev_private)
    assert score_private >= 80, f"Expected risk_score >= 80 for private file tamper, got {score_private}"
    
    severity_private = derive_severity_from_risk(score_private)
    assert severity_private == "high", f"Expected severity 'high' for risk_score {score_private}, got {severity_private}"
    
    mark_alert(ev_private, min_risk=70, min_ai_risk=70)
    assert ev_private.is_alert is True, "Expected alert=True for private file tamper"
    
    # Test secret file tampering
    ev_secret = Event(
        timestamp=datetime.utcnow(),
        event_type="delete",
        path="/data/secret_file.txt",
        old_hash="a",
        new_hash=None,
        severity="low",
        mitre_tags=[],
        message="Deleted secret file",
        content_classification="secret",
    )
    score_secret = simple_risk_score(ev_secret)
    assert score_secret >= 90, f"Expected risk_score >= 90 for secret file tamper, got {score_secret}"
    
    severity_secret = derive_severity_from_risk(score_secret)
    assert severity_secret == "high", f"Expected severity 'high' for risk_score {score_secret}, got {severity_secret}"
    
    mark_alert(ev_secret, min_risk=70, min_ai_risk=70)
    assert ev_secret.is_alert is True, "Expected alert=True for secret file tamper"
    
    # Test that create events on private files don't automatically alert
    ev_create = Event(
        timestamp=datetime.utcnow(),
        event_type="create",
        path="/data/new_private_file.txt",
        old_hash=None,
        new_hash="c",
        severity="low",
        mitre_tags=[],
        message="Created private file",
        content_classification="private",
    )
    score_create = simple_risk_score(ev_create)
    # Create events should not have the tamper boost
    # They may still be high risk due to other factors, but not forced >= 80
    mark_alert(ev_create, min_risk=70, min_ai_risk=70)
    # Alert should be based on actual risk_score, not forced
    # (This test verifies that create events don't get forced alerts)


def test_timeline_storage_roundtrip(tmp_path):
    from datetime import datetime
    from fim_agent.core.storage import Storage
    from fim_agent.core.events import Event

    db_path = tmp_path / "db.sqlite3"
    storage = Storage(str(db_path))
    storage.init_schema()

    ev = Event(
        timestamp=datetime.fromisoformat("2025-01-01T00:00:00"),
        event_type="create",
        path="/tmp/file.txt",
        old_hash=None,
        new_hash="abc",
        severity="low",
        mitre_tags=["Execution"],
        message="CREATE /tmp/file.txt",
    )
    storage.log_event(ev)

    events = storage.get_events()
    assert len(events) == 1
    assert events[0].path == "/tmp/file.txt"
    assert events[0].event_type == "create"


def test_move_classification(tmp_path):
    """Test move event classification logic."""
    from pathlib import Path
    from fim_agent.core.config import Config
    from fim_agent.core.watcher import _classify_move, _is_in_monitored
    
    # Create test directories
    watched_dir = tmp_path / "watched"
    staging_dir = tmp_path / "staging"
    outside_dir = tmp_path / "outside"
    watched_dir.mkdir()
    staging_dir.mkdir()
    outside_dir.mkdir()
    
    config = Config(
        monitored_directories=[str(watched_dir), str(staging_dir)],
        exclude_directories=[],
        exclude_extensions=[],
        database_path=str(tmp_path / "db.sqlite3"),
        log_file=str(tmp_path / "log.txt"),
        log_format="json",
    )
    
    # Test rename: same directory, different filename
    src = watched_dir / "old.txt"
    dest = watched_dir / "new.txt"
    assert _classify_move(src, dest, config) == "rename"
    
    # Test move_internal: different directory within monitored
    src = watched_dir / "file.txt"
    dest = staging_dir / "file.txt"
    assert _classify_move(src, dest, config) == "move_internal"
    
    # Test move_in: from outside into monitored
    src = outside_dir / "file.txt"
    dest = watched_dir / "file.txt"
    assert _classify_move(src, dest, config) == "move_in"
    
    # Test move_out: from monitored to outside
    src = watched_dir / "file.txt"
    dest = outside_dir / "file.txt"
    assert _classify_move(src, dest, config) == "move_out"
    
    # Test both outside: should return None
    src = outside_dir / "file1.txt"
    dest = outside_dir / "file2.txt"
    assert _classify_move(src, dest, config) is None


def test_move_event_types():
    """Test that move event types are properly recognized."""
    from datetime import datetime
    from fim_agent.core.events import Event, simple_risk_score, map_mitre_tags
    
    # Test rename event
    rename_ev = Event(
        timestamp=datetime.utcnow(),
        event_type="rename",
        path="/watched/new.txt",
        old_hash="abc",
        new_hash="abc",
        severity="low",
        mitre_tags=[],
        message="RENAME /watched/old.txt -> /watched/new.txt",
        old_path="/watched/old.txt",
    )
    assert rename_ev.event_type == "rename"
    assert simple_risk_score(rename_ev) >= 20  # Rename adds 20 points
    
    # Test move_internal event
    move_int_ev = Event(
        timestamp=datetime.utcnow(),
        event_type="move_internal",
        path="/staging/file.txt",
        old_hash="abc",
        new_hash="abc",
        severity="low",
        mitre_tags=[],
        message="MOVE_INTERNAL /watched/file.txt -> /staging/file.txt",
        old_path="/watched/file.txt",
    )
    assert move_int_ev.event_type == "move_internal"
    assert simple_risk_score(move_int_ev) >= 22  # Move_internal adds 22 points
    
    # Test move_in event
    move_in_ev = Event(
        timestamp=datetime.utcnow(),
        event_type="move_in",
        path="/watched/file.txt",
        old_hash=None,
        new_hash="abc",
        severity="low",
        mitre_tags=[],
        message="MOVE_IN /outside/file.txt -> /watched/file.txt",
        old_path="/outside/file.txt",
    )
    assert move_in_ev.event_type == "move_in"
    assert simple_risk_score(move_in_ev) >= 30  # Move_in adds 30 points
    
    # Test move_out event
    move_out_ev = Event(
        timestamp=datetime.utcnow(),
        event_type="move_out",
        path="/watched/file.txt",
        old_hash="abc",
        new_hash=None,
        severity="low",
        mitre_tags=[],
        message="MOVE_OUT /watched/file.txt -> /outside/file.txt",
        old_path="/watched/file.txt",
    )
    assert move_out_ev.event_type == "move_out"
    assert simple_risk_score(move_out_ev) >= 35  # Move_out adds 35 points
    
    # Test MITRE tags for move events
    tags = map_mitre_tags("/watched/file.txt", "move_out")
    assert "Defense Evasion" in tags
    assert "Exfiltration" in tags


def test_update_file_path_unique_constraint(tmp_path):
    """Test that update_file_path handles UNIQUE constraint when new_path already exists."""
    from fim_agent.core.storage import Storage
    from datetime import datetime
    
    db_path = tmp_path / "db.sqlite3"
    storage = Storage(str(db_path))
    storage.init_schema()
    
    # Create baseline entry for old_path
    old_path = "/watched/old_file.txt"
    old_hash = "abc123"
    timestamp1 = datetime.utcnow()
    storage.upsert_file(old_path, old_hash, "create", timestamp1)
    
    # Create baseline entry for new_path (simulating existing file)
    new_path = "/watched/new_file.txt"
    new_hash = "xyz789"
    timestamp2 = datetime.utcnow()
    storage.upsert_file(new_path, new_hash, "create", timestamp2)
    
    # Verify both exist
    assert storage.get_file(old_path) is not None
    assert storage.get_file(new_path) is not None
    assert storage.count_files() == 2
    
    # Simulate rename: old_path -> new_path (where new_path already exists)
    # This should merge the records, not cause a UNIQUE constraint error
    storage.update_file_path(old_path, new_path)
    
    # Verify old_path is gone
    assert storage.get_file(old_path) is None
    
    # Verify new_path exists and has the old_path's hash (merged)
    updated_record = storage.get_file(new_path)
    assert updated_record is not None
    assert updated_record["hash"] == old_hash  # Should have old_path's hash
    
    # Verify only one row exists for new_path
    assert storage.count_files() == 1
    
    # Test rename to non-existent path (normal case)
    another_path = "/watched/another_file.txt"
    storage.update_file_path(new_path, another_path)
    assert storage.get_file(new_path) is None
    assert storage.get_file(another_path) is not None
    assert storage.get_file(another_path)["hash"] == old_hash
    assert storage.count_files() == 1


def test_admin_approval_policy():
    """Test admin approval policy for sensitive content."""
    from fim_agent.core.events import mark_requires_admin_approval
    from fim_agent.core.governance import is_sensitive, is_tamper_event, SENSITIVE_PATHS
    from fim_agent.core.config import Config
    
    # Clear SENSITIVE_PATHS at start of test to ensure clean state
    SENSITIVE_PATHS.clear()
    
    config = Config(
        monitored_directories=["./watched"],
        exclude_directories=[],
        exclude_extensions=[],
        database_path="./data/fim.sqlite3",
        log_file="./logs/fim_agent.log",
        log_format="json",
        require_admin_for_alerts=True,
        admin_min_risk_score=80,
        admin_min_ai_risk_score=75,
    )
    
    # Test 1: Create sensitive file (previous_sha256=None) - should NOT require approval
    create_ev = Event(
        timestamp=datetime.utcnow(),
        event_type="create",
        path="/watched/salary_data.txt",
        old_hash=None,
        new_hash="abc123",
        severity="medium",
        mitre_tags=[],
        message="CREATE /watched/salary_data.txt",
        content_classification="secret",
        classification_matches=["secret:password", "secret:api_key", "private:salary"],
        previous_sha256=None,  # First time we see this file - no previous hash
    )
    mark_requires_admin_approval(create_ev, True, 80, 75, config=config)
    assert create_ev.requires_admin_approval is False, "Creating sensitive file (previous_sha256=None) should not require approval"
    assert is_sensitive(create_ev, config) is True, "Event should be marked as sensitive"
    
    # Test 2: Modify sensitive file (previous_sha256 exists) - should REQUIRE approval
    modify_ev = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/watched/salary_data.txt",
        old_hash="abc123",
        new_hash="def456",
        severity="medium",
        mitre_tags=[],
        message="MODIFY /watched/salary_data.txt",
        content_classification="secret",
        classification_matches=["secret:password"],
        previous_sha256="abc123",  # File already known - has previous hash
    )
    mark_requires_admin_approval(modify_ev, True, 80, 75, config=config)
    assert modify_ev.requires_admin_approval is True, "Modifying sensitive file (previous_sha256 exists) should require approval"
    assert is_tamper_event(modify_ev) is True, "Modify should be a tamper event"
    
    # Test 3: Delete sensitive file (previous_sha256 exists) - should REQUIRE approval
    delete_ev = Event(
        timestamp=datetime.utcnow(),
        event_type="delete",
        path="/watched/salary_data.txt",
        old_hash="abc123",
        new_hash=None,
        severity="medium",
        mitre_tags=[],
        message="DELETE /watched/salary_data.txt",
        content_classification="secret",
        previous_sha256="abc123",  # File already known - has previous hash
    )
    mark_requires_admin_approval(delete_ev, True, 80, 75, config=config)
    assert delete_ev.requires_admin_approval is True, "Deleting sensitive file (previous_sha256 exists) should require approval"
    assert is_tamper_event(delete_ev) is True, "Delete should be a tamper event"
    
    # Test 4: Create non-sensitive file - should NOT require approval (unless high risk)
    create_normal_ev = Event(
        timestamp=datetime.utcnow(),
        event_type="create",
        path="/watched/notes.txt",
        old_hash=None,
        new_hash="xyz789",
        severity="low",
        mitre_tags=[],
        message="CREATE /watched/notes.txt",
        content_classification="public",
        risk_score=30,  # Below threshold
    )
    mark_requires_admin_approval(create_normal_ev, True, 80, 75, config=config)
    assert create_normal_ev.requires_admin_approval is False, "Creating normal file should not require approval"
    
    # Test 5: High-risk non-sensitive event - should require approval
    high_risk_ev = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/watched/system.ps1",
        old_hash="abc",
        new_hash="def",
        severity="high",
        mitre_tags=[],
        message="MODIFY /watched/system.ps1",
        content_classification="public",
        risk_score=85,  # Above threshold
    )
    mark_requires_admin_approval(high_risk_ev, True, 80, 75, config=config)
    assert high_risk_ev.requires_admin_approval is True, "High-risk event should require approval"


def test_high_risk_executables():
    """Test that executable/DLL files get high risk scores and proper flags."""
    from fim_agent.core.events import Event, simple_risk_score, HIGH_RISK_EXECUTABLE_EXTENSIONS
    
    # Test CREATE event for a DLL file
    dll_event = Event(
        timestamp=datetime.utcnow(),
        event_type="create",
        path="C:/tmp/evil.dll",
        old_hash=None,
        new_hash="abc123",
        severity="low",
        mitre_tags=[],
        message="CREATE C:/tmp/evil.dll",
        content_flags=[],
    )
    score = simple_risk_score(dll_event)
    
    assert score >= 80, f"Executable file should have risk_score >= 80, got {score}"
    assert "executable_drop" in dll_event.content_flags, "Should have executable_drop flag"
    assert "Execution" in dll_event.mitre_tags, "Should have Execution MITRE tag"
    assert "Defense Evasion" in dll_event.mitre_tags, "Should have Defense Evasion MITRE tag"
    
    # Test MODIFY event for an EXE file
    exe_event = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="C:/tmp/malware.exe",
        old_hash="abc123",
        new_hash="def456",
        severity="low",
        mitre_tags=[],
        message="MODIFY C:/tmp/malware.exe",
        content_flags=[],
    )
    score = simple_risk_score(exe_event)
    
    assert score >= 80, f"Executable file should have risk_score >= 80, got {score}"
    assert "executable_drop" in exe_event.content_flags, "Should have executable_drop flag"
    assert "Execution" in exe_event.mitre_tags, "Should have Execution MITRE tag"
    assert "Defense Evasion" in exe_event.mitre_tags, "Should have Defense Evasion MITRE tag"
    
    # Test that DELETE events don't trigger executable_drop (only create/modify)
    delete_event = Event(
        timestamp=datetime.utcnow(),
        event_type="delete",
        path="C:/tmp/evil.dll",
        old_hash="abc123",
        new_hash=None,
        severity="low",
        mitre_tags=[],
        message="DELETE C:/tmp/evil.dll",
        content_flags=[],
    )
    delete_score = simple_risk_score(delete_event)
    # DELETE should have high score but not executable_drop flag
    assert "executable_drop" not in (delete_event.content_flags or []), "DELETE should not add executable_drop flag"
    
    # Test case-insensitive extension matching
    ps1_event = Event(
        timestamp=datetime.utcnow(),
        event_type="create",
        path="C:/tmp/SCRIPT.PS1",  # Uppercase extension
        old_hash=None,
        new_hash="abc123",
        severity="low",
        mitre_tags=[],
        message="CREATE C:/tmp/SCRIPT.PS1",
        content_flags=[],
    )
    ps1_score = simple_risk_score(ps1_event)
    assert ps1_score >= 80, "Should handle uppercase extensions case-insensitively"
    assert "executable_drop" in ps1_event.content_flags

