from markupsafe import escape
from datetime import datetime

from flask import Blueprint, abort, render_template, request
from flask_login import current_user, login_required

from .models import Assignment, Course, CourseTA, Enrollment, Submission, User, db
from .policy import requires

bp = Blueprint("staff", __name__)


@bp.before_request
def instructors_only_for_writes():
    if request.path.startswith("/staff/") and request.method == "POST":
        if not current_user.is_authenticated:
            abort(401)
        if current_user.role != "instructor":
            abort(403)


@bp.post("/staff/release/<int:cid>")
@requires("release_grades", load=lambda cid: db.get_or_404(Course, cid))
@login_required
def release(cid):
    course = db.get_or_404(Course, cid)
    for sub in Submission.query.join(Assignment).filter(Assignment.course_id == cid):
        sub.released = True
    db.session.commit()
    return f"Grades released for {escape(course.code)}."


@bp.get("/staff/assignments/new")
@requires("create_assignment", load=lambda: Course.query.filter_by(
    instructor_id=current_user.id).first())
def new_assignment_form():
    return render_template("course_new_assignment.html")


@bp.post("/staff/assignments/new")
@requires("create_assignment", load=lambda: db.get_or_404(
    Course, request.form.get("course_id", type=int)))
def new_assignment():
    cid = int(request.form["course_id"])
    deadline = datetime.fromisoformat(request.form["deadline"])
    db.session.add(Assignment(course_id=cid, title=request.form["title"],
                              deadline=deadline))
    db.session.commit()
    return f"Assignment added to course {cid}."


@bp.get("/registrar-x9k2")
@requires("manage_roles")
@login_required
def registrar_console():
    return render_template("registrar_console.html", users=User.query.all())


@bp.post("/registrar-x9k2/role")
@requires("manage_roles", load=lambda: User.query.filter_by(
    username=request.form.get("username", "")).first_or_404())
@login_required
def set_role():
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    user.role = request.form["role"]
    db.session.commit()
    return f"Role of {escape(user.username)} set to {escape(user.role)}."


@bp.post("/registrar-x9k2/enroll")
@requires("enroll", load=lambda: db.get_or_404(
    Course, request.form.get("course_id", type=int)))
@login_required
def enroll():
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    cid = int(request.form["course_id"])
    db.session.add(Enrollment(user_id=user.id, course_id=cid))
    db.session.commit()
    return f"{escape(user.username)} enrolled in course {cid}."


@bp.get("/registrar")
@requires("manage_roles")
@login_required
def registrar():
    return render_template("registrar.html", courses=Course.query.all())


@bp.post("/courses/<int:cid>/staff/add")
@requires("assign_staff", load=lambda cid: db.get_or_404(Course, cid))
@login_required
def add_ta(cid):
    course = db.get_or_404(Course, cid)
    user = User.query.filter_by(username=request.form.get("username", "")).first_or_404()
    existing = CourseTA.query.filter_by(user_id=user.id, course_id=cid).first()
    if existing is None:
        db.session.add(CourseTA(user_id=user.id, course_id=cid))
        db.session.commit()
    return f"{escape(user.username)} added as TA of {escape(course.code)}."
