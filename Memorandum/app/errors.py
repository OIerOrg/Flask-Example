# app/errors.py
from flask import Blueprint, render_template

errors = Blueprint('errors', __name__)

@errors.app_errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

@errors.app_errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404
