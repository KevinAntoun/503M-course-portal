from markupsafe import escape
from flask import Blueprint, abort, render_template, request, session
from flask_login import current_user, login_required

from .models import Assignment, Course, Submission, db, utcnow
from .policy import requires

bp = Blueprint("courses", __name__)


@bp.get("/")
@requires(None)
@login_required
def dashboard():
    ids = current_user.enrolled_in | current_user.staff_of
    courses = Course.query.filter(Course.id.in_(ids)).all() if ids else []
    return render_template("dashboard.html", courses=courses)


@bp.get("/courses/<int:cid>/materials")
@requires("view_material", load=lambda cid: db.get_or_404(Course, cid))
@login_required
def materials(cid):
    return render_template("materials.html", course=db.get_or_404(Course, cid))


@bp.post("/assignments/<int:aid>/submit")
@requires("submit", load=lambda aid: db.get_or_404(Assignment, aid))
@login_required
def submit(aid):
    assignment = db.get_or_404(Assignment, aid)
    sub = Submission.query.filter_by(assignment_id=aid, student_id=current_user.id).first()
    if sub is None:
        sub = Submission(assignment_id=aid, student_id=current_user.id)
        db.session.add(sub)
    sub.body = request.form.get("body", "")
    db.session.commit()
    return render_template("submission.html", sub=sub)


@bp.get("/submissions/<int:sid>")
@requires(None, load=lambda sid: Submission.query.filter_by(
    id=sid, student_id=current_user.id).first_or_404())
@login_required
def view_submission(sid):
    sub = Submission.query.get_or_404(sid)
    return render_template("submission.html", sub=sub)


@bp.post("/submissions/<int:sid>/grade")
@requires("grade", load=lambda sid: db.get_or_404(Submission, sid))
@login_required
def grade(sid):
    sub = db.get_or_404(Submission, sid)
    sub.grade = request.form.get("grade")
    db.session.commit()
    return f"Grade for submission {sub.id} set to {escape(sub.grade)}."


@bp.post("/submissions/<int:sid>/change")
@requires("change_grade", load=lambda sid: db.get_or_404(Submission, sid))
@login_required
def change(sid):
    sub = db.get_or_404(Submission, sid)
    grade = request.form.get("grade", "")
    if not grade:
        abort(400)
    session["pending_grade_change"] = {"sid": sid, "grade": grade}
    return render_template("change_confirm.html", sub=sub, grade=grade)


@bp.post("/submissions/<int:sid>/change/confirm")
@requires("change_grade", load=lambda sid: db.get_or_404(Submission, sid))
@login_required
def change_confirm(sid):
    pending = session.get("pending_grade_change")
    grade = request.form.get("grade", "")
    if not pending or pending.get("sid") != sid or pending.get("grade") != grade:
        abort(403)
    session.pop("pending_grade_change", None)
    sub = db.get_or_404(Submission, sid)
    if request.form.get("confirmed") == "true":
        sub.grade = grade
        db.session.commit()
        return f"Grade for submission {sub.id} changed to {escape(sub.grade)}."
    return "Change cancelled."


@bp.get("/gradebook/<int:cid>")
@requires("view_gradebook", load=lambda cid: db.get_or_404(Course, cid))
def gradebook(cid):
    course = db.get_or_404(Course, cid)
    subs = (Submission.query.join(Assignment)
            .filter(Assignment.course_id == cid).all())
    return render_template("gradebook.html", course=course, subs=subs)
