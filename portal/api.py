from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from .models import User, db
from .policy import requires

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.get("/me")
@requires(None)
@login_required
def me():
    return jsonify(id=current_user.id, username=current_user.username,
                   role=current_user.role, email=current_user.email)


@bp.put("/users/<int:uid>/email")
@requires(None, load=lambda uid: User.query.filter(
    User.id == uid, User.id == current_user.id).first_or_404())
@login_required
def set_email(uid):
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    if not isinstance(email, str):
        return jsonify(detail="invalid email"), 400
    email = email.strip()
    if not email or "@" not in email:
        return jsonify(detail="invalid email"), 400
    duplicate = User.query.filter(
        db.func.lower(User.email) == email.lower(), User.id != current_user.id
    ).first()
    if duplicate is not None:
        return jsonify(detail="invalid email"), 400
    user = db.session.get(User, current_user.id)
    user.email = email
    db.session.commit()
    return jsonify(status="ok")
