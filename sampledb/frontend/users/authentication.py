# coding: utf-8
"""

"""

import flask
import flask_login

from sampledb.frontend import frontend
from sampledb.logic.authentication import login
from sampledb.frontend.users_forms import SigninForm, SignoutForm
from sampledb.models import User
from sampledb import login_manager


@login_manager.user_loader
def load_user(user_id):
    try:
        user_id = int(user_id)
    except ValueError:
        return None
    return User.query.get(user_id)


@frontend.route('/users/me/sign_in', methods=['GET', 'POST'])
def sign_in():
    if flask_login.current_user.is_authenticated:
        return flask.redirect(flask.url_for('.index'))
    form = SigninForm()
    has_errors = False
    has_authentication_error = False
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember_me = form.remember_me.data
        user = login(username, password)
        if user:
            flask_login.login_user(user, remember=remember_me)
            next_url = flask.request.args.get('next', flask.url_for('.index'))
            index_url = flask.url_for('.index')
            if not next_url.startswith('/') or not all(c in '/=?&_' or c.isalnum() for c in next_url):
                next_url = index_url
            return flask.redirect(next_url)
        has_errors = True
        has_authentication_error = True
    elif form.errors:
        has_errors = True
    return flask.render_template('sign_in.html', form=form, has_errors=has_errors, has_authentication_error=has_authentication_error)


@frontend.route('/users/me/sign_out', methods=['GET', 'POST'])
@flask_login.login_required
def sign_out():
    form = SignoutForm()
    if form.validate_on_submit():
        flask_login.logout_user()
        return flask.redirect(flask.url_for('.index'))
    return flask.render_template('sign_out.html')
