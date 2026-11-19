"""Access control policy for the Course Portal.

Part 4 of Level 4 asks you to write this file.

  ROLE_PERMISSIONS   RBAC: which permissions each role could ever use
  CONDITIONS         ABAC: one function per permission, (user, obj, ctx) -> bool
  can()              step 1 RBAC, step 2 ABAC; anything unknown is denied
  requires()         declare the permission a route needs, next to the route
  install(app)       one before_request hook that checks every request

The application-wide hook enforces this model on every protected route.
"""

import secrets
from datetime import timedelta
from ipaddress import ip_address, ip_network

from flask import request, session
from flask_login import current_user
from werkzeug.exceptions import NotFound

from .models import SubmissionExtension, db, utcnow

ROLE_PERMISSIONS = {
    "student": {"view_material", "submit", "view_grade"},
    "ta": {"view_material", "grade", "view_gradebook"},
    "instructor": {
        "view_material", "create_assignment", "grade", "change_grade",
        "view_gradebook", "release_grades",
    },
    "registrar": {"enroll", "manage_roles", "assign_staff"},
    "chair": {"view_gradebook"},
}


def _can_view_material(user, obj, ctx):
    return obj is not None and (obj.id in user.enrolled_in or obj.id in user.staff_of)


def _can_submit(user, obj, ctx):
    if obj is None or obj.course_id not in user.enrolled_in:
        return False
    deadline = obj.deadline
    extension = db.session.get(SubmissionExtension, (user.id, obj.id))
    if extension is not None and extension.approved:
        deadline += timedelta(days=3)
    return utcnow() < deadline


def _can_view_grade(user, obj, ctx):
    return obj is not None and obj.student_id == user.id and obj.released


def _can_create_assignment(user, obj, ctx):
    return obj is not None and obj.id in user.teaches


def _can_grade(user, obj, ctx):
    return (
        obj is not None
        and obj.course_id in user.staff_of
        and not obj.released
        and not (user.role == "ta" and obj.course_id in user.enrolled_in)
    )


def _can_change_grade(user, obj, ctx):
    return (
        obj is not None
        and obj.course_id in user.teaches
        and obj.released
        and utcnow() < obj.course.grade_deadline
        and ctx.get("network") == "campus"
    )


def _can_enroll(user, obj, ctx):
    return True


def _can_view_gradebook(user, obj, ctx):
    return (
        obj is not None
        and (
            user.department == obj.department
            if user.role == "chair"
            else obj.id in user.staff_of
        )
    )


def _can_release_grades(user, obj, ctx):
    return obj is not None and obj.id in user.teaches


def _can_manage_roles(user, obj, ctx):
    return True


def _can_assign_staff(user, obj, ctx):
    return True

CONDITIONS = {
    "view_material": _can_view_material,
    "submit": _can_submit,
    "view_grade": _can_view_grade,
    "create_assignment": _can_create_assignment,
    "grade": _can_grade,
    "change_grade": _can_change_grade,
    "enroll": _can_enroll,
    "view_gradebook": _can_view_gradebook,
    "release_grades": _can_release_grades,
    "manage_roles": _can_manage_roles,
    "assign_staff": _can_assign_staff,
}


def can(user, perm, obj=None, ctx=None):
    if user is None or not user.is_authenticated:
        return False
    if perm not in ROLE_PERMISSIONS.get(user.role, set()):
        return False
    condition = CONDITIONS.get(perm)
    if condition is None:
        return False
    return bool(condition(user, obj, {} if ctx is None else ctx))


def requires(perm, load=None):
    def deco(f):
        f._policy_permission = perm
        f._policy_loader = load
        return f
    return deco


def install(app):
    campus_networks = (ip_network("10.0.0.0/8"), ip_network("127.0.0.0/8"))

    def deny(status):
        app.logger.warning(
            "Access denied: status=%s method=%s path=%s",
            status, request.method, request.path,
        )
        return {401: "Unauthorized", 403: "Forbidden", 404: "Not Found"}[status], status

    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    def handle_access_error(error):
        return deny(error.code)

    @app.before_request
    def enforce_policy():
        # Validate before every early return, including public and static routes.
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            expected = session.get("csrf_token")
            candidates = (request.form.get("csrf_token"), request.headers.get("X-CSRF-Token"))
            if not isinstance(expected, str) or not expected:
                return deny(403)
            if not any(
                isinstance(token, str)
                and secrets.compare_digest(expected.encode("utf-8"), token.encode("utf-8"))
                for token in candidates
            ):
                return deny(403)
        elif "csrf_token" not in session:
            # Anonymous forms, including login, also submit a token.
            session["csrf_token"] = secrets.token_urlsafe(32)

        if request.endpoint == "static":
            return None
        if request.endpoint is None:
            return deny(404)
        view = app.view_functions.get(request.endpoint)
        if view is None or not hasattr(view, "_policy_permission"):
            return deny(403)
        perm = view._policy_permission
        if perm == "public":
            return None
        if not current_user.is_authenticated:
            return deny(401)
        # Check the role before loading an object and exposing its existence.
        if perm is not None and (
            perm not in ROLE_PERMISSIONS.get(current_user.role, set())
            or perm not in CONDITIONS
        ):
            return deny(403)
        obj = None
        loader = getattr(view, "_policy_loader", None)
        if loader is not None:
            try:
                obj = loader(**(request.view_args or {}))
            except NotFound:
                return deny(404)
        # Only the server-observed peer address determines the network.
        try:
            address = ip_address(request.remote_addr or "")
            campus = any(address in network for network in campus_networks)
        except ValueError:
            campus = False
        ctx = {"network": "campus" if campus else "external"}
        if perm is not None and not can(current_user, perm, obj, ctx):
            return deny(403)
        return None
