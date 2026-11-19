"""Steps 25–28: three cases per rule, at least two denials each."""
from datetime import datetime, timedelta

from conftest import login
from portal.models import SubmissionExtension, db
from portal.policy import can

CAMPUS = {"network": "campus"}


def test_n1_chair_reads_department_grades(client, world):
    login(client, "chair")
    assert client.get("/gradebook/1").status_code == 200
    assert client.get("/gradebook/2").status_code == 200


def test_n1_chair_cannot_read_other_department(client, world):
    world["cmps202"].department = "EECE"
    db.session.commit()
    login(client, "chair")
    assert client.get("/gradebook/2").status_code == 403


def test_n1_chair_cannot_change_grades(client, world):
    login(client, "chair")
    for path in ("/submissions/2/grade", "/submissions/1/change",
                 "/submissions/1/change/confirm", "/staff/release/1"):
        assert client.post(path, data={"grade": "A+", "confirmed": "true"}).status_code == 403
    db.session.expire_all()
    assert world["sub_released"].grade == "B"
    assert world["sub_open_215"].released is False


def extension_for(world, approved=True):
    extension = SubmissionExtension(
        student_id=world["lina"].id,
        assignment_id=world["a3_late"].id,
        approved=approved,
    )
    db.session.add(extension)
    db.session.commit()
    return extension


def test_n2_approved_extension_allows_late_submission(client, world, monkeypatch):
    assignment = world["a3_late"]
    now = datetime(2026, 11, 19, 12)
    assignment.deadline = now - timedelta(days=2)
    extension_for(world)
    monkeypatch.setattr("portal.policy.utcnow", lambda: now)
    login(client, "lina")
    assert client.post(f"/assignments/{assignment.id}/submit",
                       data={"body": "Extended submission"}).status_code == 200


def test_n2_unapproved_extension_denies_late_submission(world, monkeypatch):
    assignment = world["a3_late"]
    monkeypatch.setattr("portal.policy.utcnow", lambda: assignment.deadline + timedelta(days=1))
    assert not can(world["lina"], "submit", assignment, CAMPUS)
    extension_for(world, approved=False)
    assert not can(world["lina"], "submit", assignment, CAMPUS)


def test_n2_extension_expires_at_three_days(world, monkeypatch):
    assignment = world["a3_late"]
    extension_for(world)
    expiry = assignment.deadline + timedelta(days=3)
    monkeypatch.setattr("portal.policy.utcnow", lambda: expiry)
    assert not can(world["lina"], "submit", assignment, CAMPUS)
    monkeypatch.setattr("portal.policy.utcnow", lambda: expiry + timedelta(seconds=1))
    assert not can(world["lina"], "submit", assignment, CAMPUS)


def test_n3_campus_instructor_can_change_released_grade(client, world):
    login(client, "dr_haddad")
    for address in ("127.0.0.1", "10.20.30.40"):
        assert client.post("/submissions/1/change", data={"grade": "A-"},
                           environ_overrides={"REMOTE_ADDR": address}).status_code == 200
    assert client.post("/submissions/1/change/confirm",
                       data={"grade": "A-", "confirmed": "true"}).status_code == 200
    db.session.expire_all()
    assert world["sub_released"].grade == "A-"


def test_n3_external_instructor_cannot_change_released_grade(client, world):
    login(client, "dr_haddad")
    assert client.post("/submissions/1/change", data={"grade": "A+"},
                       environ_overrides={"REMOTE_ADDR": "203.0.113.10"}).status_code == 403
    assert world["sub_released"].grade == "B"


def test_n3_forged_network_headers_cannot_confirm_change(client, world):
    login(client, "dr_haddad")
    assert client.post("/submissions/1/change", data={"grade": "A+"}).status_code == 200
    response = client.post(
        "/submissions/1/change/confirm",
        data={"grade": "A+", "confirmed": "true"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.10"},
        headers={"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "10.0.0.1",
                 "Forwarded": "for=127.0.0.1", "X-Network": "campus"},
    )
    assert response.status_code == 403
    db.session.expire_all()
    assert world["sub_released"].grade == "B"


def test_n4_unenrolled_ta_can_grade(client, world):
    login(client, "omar")
    assert client.post("/submissions/2/grade", data={"grade": "B+"}).status_code == 200
    db.session.expire_all()
    assert world["sub_open_215"].grade == "B+"


def test_n4_enrolled_ta_cannot_grade_own_course(client, world):
    before = world["sub_open_202"].grade
    login(client, "rana")
    assert client.post("/submissions/4/grade", data={"grade": "A+"}).status_code == 403
    db.session.expire_all()
    assert world["sub_open_202"].grade == before


def test_n4_ta_cannot_grade_unassigned_course(client, world):
    before = world["sub_open_202"].grade
    login(client, "omar")
    assert client.post("/submissions/4/grade", data={"grade": "A+"}).status_code == 403
    db.session.expire_all()
    assert world["sub_open_202"].grade == before
