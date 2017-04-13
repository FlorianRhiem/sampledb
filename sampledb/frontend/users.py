# coding: utf-8
"""

"""

import flask
import flask_login
import bcrypt

from .. import db

from . import frontend
from ..logic import user_log
from .authentication_forms import ChangeUserForm, AuthenticationForm, AuthenticationMethodForm
from ..logic.authentication import login, add_login, remove_authentication_method
from ..logic.authentication import insert_user_and_authentication_method_to_db, add_authentication_to_db
from ..logic.utils import send_confirm_email
from ..logic.security_tokens import verify_token

from ..models import Authentication, AuthenticationType, User, UserType

from .users_forms import SigninForm, SignoutForm, InvitationForm, RegistrationForm

__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'


@frontend.route('/users/me/sign_in', methods=['GET', 'POST'])
def sign_in():
    if flask_login.current_user.is_authenticated:
        return flask.redirect(flask.url_for('.index'))
    form = SigninForm()
    has_errors = False
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember_me = form.remember_me.data
        user = login(username, password)
        if user:
            flask_login.login_user(user, remember=remember_me)
            next_url = flask.request.args.get('next', '/')
            index_url = flask.url_for('.index')
            if not next_url.startswith('/') or not all(c in '/=?&_' or c.isalnum() for c in next_url):
                next_url = index_url
            return flask.redirect(next_url)
        has_errors = True
    elif form.errors:
        has_errors = True
    return flask.render_template('sign_in.html', form=form, has_errors=has_errors)


@frontend.route('/users/me/sign_out', methods=['GET', 'POST'])
@flask_login.login_required
def sign_out():
    form = SignoutForm()
    if form.validate_on_submit():
        flask_login.logout_user()
        return flask.redirect(flask.url_for('.index'))
    return flask.render_template('sign_out.html')


@frontend.route('/users/invitation', methods=['GET', 'POST'])
def invitation_route():
    if flask_login.current_user.is_authenticated:
        return invitation()
    elif 'token' in flask.request.args:
        return registration()
    else:
        return flask.abort(403)


def invitation():
    # TODO: initial instrument permissions?
    invitation_form = InvitationForm()
    if flask.request.method == "GET":
        #  GET (invitation dialog )
        has_success = False
        return flask.render_template('invitation.html', invitation_form=invitation_form, has_success=has_success)
    if flask.request.method == "POST":
        # POST (send invitation)
        has_success = False
        has_error = False
        if invitation_form.validate_on_submit():
            email = invitation_form.email.data
            if '@' not in email:
                has_error = True
            else:
                has_success = True
                # send confirm link
                send_confirm_email(invitation_form.email.data, None, 'invitation')
        else:
            has_error = True
        return flask.render_template('invitation.html', invitation_form=invitation_form, has_success=has_success,
                                     has_error=has_error)
    return flask.render_template('index.html')


def registration():
    token = flask.request.args.get('token')
    email = verify_token(token, salt='invitation', secret_key=flask.current_app.config['SECRET_KEY'])
    if email is None or '@' not in email:
        return flask.abort(404)
    registration_form = RegistrationForm()
    if registration_form.email.data is None or registration_form.email.data == "":
        registration_form.email.data = email
    has_error = False
    if flask.request.method == "GET":
        # confirmation dialog
        return flask.render_template('registration.html', registration_form=registration_form, has_error=has_error)
    if flask.request.method == "POST":
        # redirect or register user and redirect
        has_error = False
        if registration_form.email.data != email:
            has_error = True
            return flask.render_template('registration.html', registration_form=registration_form, has_error=has_error)
        if registration_form.validate_on_submit():
            name = str(registration_form.name.data)
            user = User(name, email, UserType.PERSON)
            # check, if email in authentication-method already exists
            authentication_method = Authentication.query.filter(Authentication.login['login'].astext == registration_form.email.data).first()
            # no user with this name and contact email in db => add to db
            if authentication_method is None:
                u = User(str(user.name).title(), user.email, user.type)
                insert_user_and_authentication_method_to_db(u, registration_form.password.data, email,
                                                            AuthenticationType.EMAIL)
                flask.flash('registration successfully')
                return flask.redirect(flask.url_for('frontend.index'))
            else:
                # found email-authentication, change password
                pw_hash = bcrypt.hashpw(registration_form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                authentication_method.login = {'login': email, 'bcrypt_hash': pw_hash}
                db.session.add(authentication_method)
                db.session.commit()
                return flask.redirect(flask.url_for('frontend.index'))
        else:
            return flask.render_template('registration.html', registration_form=registration_form, has_error=has_error)
    return flask.render_template('index.html')


@frontend.route('/users/me')
@flask_login.login_required
def current_user_profile():
    return flask.redirect(flask.url_for('.user_profile', user_id=flask_login.current_user.id))


@frontend.route('/users/<int:user_id>')
@flask_login.login_required
def user_profile(user_id):
    # TODO: this is a placeholder for now. user profiles will be implemented in the future.
    return flask.redirect(flask.url_for('.index'))


@frontend.route('/users/me/preferences', methods=['GET', 'POST'])
@flask_login.login_required
def user_me_preferences():
    return flask.redirect(flask.url_for('.user_preferences', user_id=flask_login.current_user.id))


@frontend.route('/users/<int:user_id>/preferences', methods=['GET', 'POST'])
@flask_login.login_required
def user_preferences(user_id=None):
    if user_id is None:
        return flask.redirect(flask.url_for('.user_preferences', user_id=flask_login.current_user.id))
    if user_id != flask_login.current_user.id:
        user = User.query.filter_by(id=user_id).first()
        return flask.abort(403)
    else:
        user = flask_login.current_user
    authentication_methods = Authentication.query.filter(Authentication.user_id == user_id).all()
    change_user_form = ChangeUserForm()
    authentication_form = AuthenticationForm()
    authentication_method_form = AuthenticationMethodForm()
    if change_user_form.name.data is None or change_user_form.name.data == "":
        change_user_form.name.data = user.name
    if change_user_form.email.data is None or change_user_form.email.data == "":
        change_user_form.email.data = user.email
    if 'change' in flask.request.form and flask.request.form['change'] == 'Change':
        if change_user_form.validate_on_submit():
            if change_user_form.name.data != user.name:
                u = user
                u.name = str(change_user_form.name.data)
                db.session.add(u)
                db.session.commit()
                user_log.edit_user_preferences(user_id=user_id)
            if change_user_form.email.data != user.email:
                # send confirm link
                send_confirm_email(change_user_form.email.data, user.id, 'edit_profile')
            return flask.redirect(flask.url_for('frontend.index'))
    if 'remove' in flask.request.form and flask.request.form['remove'] == 'Remove':
        authentication_method_id = authentication_method_form.id.data
        if authentication_method_form.validate_on_submit():
            try:
                remove_authentication_method(user_id, authentication_method_id)
            except Exception as e:
                return flask.render_template('preferences.html', user=user, change_user_form=change_user_form,
                                             authentication_method_form=authentication_method_form,
                                             authentication_form=authentication_form,
                                             authentications=authentication_methods, error=str(e))
            user_log.edit_user_preferences(user_id=user_id)
            authentication_methods = Authentication.query.filter(Authentication.user_id == user_id).all()
    if 'add' in flask.request.form and flask.request.form['add'] == 'Add':
        if authentication_form.validate_on_submit():
            # check, if login already exists
            all_authentication_methods = {
                'E': AuthenticationType.EMAIL,
                'L': AuthenticationType.LDAP,
                'O': AuthenticationType.OTHER
            }
            if authentication_form.authentication_method.data not in all_authentication_methods:
                return flask.abort(400)
            authentication_method = all_authentication_methods[authentication_form.authentication_method.data]
            # check, if additional authentication is correct
            try:
                add_login(user_id, authentication_form.login.data, authentication_form.password.data, authentication_method)
            except Exception as e:
                return flask.render_template('preferences.html', user=user, change_user_form=change_user_form,
                                             authentication_method_form=authentication_method_form,
                                             authentication_form=authentication_form,
                                             authentications=authentication_methods, error_add=str(e))
            authentication_methods = Authentication.query.filter(Authentication.user_id == user_id).all()
    return flask.render_template('preferences.html', user=user, change_user_form=change_user_form, authentication_method_form=authentication_method_form,
                                 authentication_form=authentication_form, authentications=authentication_methods)


@frontend.route('/users/confirm-email', methods=['GET'])
def confirm_email():
    salt = flask.request.args.get('salt')
    token = flask.request.args.get('token')
    data = verify_token(token, salt=salt, secret_key=flask.current_app.config['SECRET_KEY'])
    if data is None:
        return flask.abort(404)
    else:
        if len(data) != 2:
            return flask.abort(400)
        email = data[0]
        user_id = data[1]
        if salt == 'edit_profile':
            user = User.query.get(user_id)
            user.email = email
            db.session.add(user)
        elif salt == 'add_login':
            auth = Authentication.query.filter(Authentication.user_id == user_id,
                                               Authentication.login['login'].astext == email).first()
            auth.confirmed = True
            db.session.add(auth)
        else:
            return flask.abort(400)
        db.session.commit()
        user_log.edit_user_preferences(user_id=user_id)
        return flask.redirect(flask.url_for('.user_preferences', user_id=user_id))


@frontend.route('/users/me/activity')
@flask_login.login_required
def current_user_activity():
    return flask.redirect(flask.url_for('.user_activity', user_id=flask_login.current_user.id))


@frontend.route('/users/<int:user_id>/activity')
@flask_login.login_required
def user_activity(user_id):
    if user_id != flask_login.current_user.id and not flask_login.current_user.is_admin:
        return flask.abort(403)
    user_log_entries = user_log.get_user_log_entries(user_id)
    return flask.render_template('user_activity.html', user_log_entries=user_log_entries, UserLogEntryType=user_log.UserLogEntryType)
