# coding: utf-8
"""

"""

import secrets

import flask
import flask_login
import sqlalchemy.sql.expression

from ... import db

from .. import frontend
from ..authentication_forms import ChangeUserForm, AuthenticationForm, AuthenticationMethodForm
from ..users_forms import RequestPasswordResetForm, PasswordForm, AuthenticationPasswordForm
from ..objects_forms import ObjectPermissionsForm, ObjectUserPermissionsForm, ObjectGroupPermissionsForm, ObjectProjectPermissionsForm
from .forms import NotificationModeForm, OtherSettingsForm, CreateAPITokenForm

from ...logic import user_log
from ...logic.authentication import add_authentication_method, remove_authentication_method, change_password_in_authentication_method, add_api_token
from ...logic.users import get_user, get_users
from ...logic.utils import send_confirm_email, send_recovery_email
from ...logic.security_tokens import verify_token
from ...logic.object_permissions import Permissions, get_default_permissions_for_users, set_default_permissions_for_user, get_default_permissions_for_groups, set_default_permissions_for_group, get_default_permissions_for_projects, set_default_permissions_for_project, default_is_public, set_default_public
from ...logic.projects import get_user_projects, get_project
from ...logic.groups import get_user_groups, get_group
from ...logic.errors import GroupDoesNotExistError, UserDoesNotExistError, ProjectDoesNotExistError
from ...logic.notifications import NotificationMode, NotificationType, get_notification_modes, set_notification_mode_for_type
from ...logic.settings import get_user_settings, set_user_settings

from ...models import Authentication, AuthenticationType


@frontend.route('/users/me/preferences', methods=['GET', 'POST'])
def user_me_preferences():
    if flask_login.current_user.is_authenticated:
        return flask.redirect(flask.url_for('.user_preferences', user_id=flask_login.current_user.id))
    return email_for_resetting_password()


@frontend.route('/users/<int:user_id>/preferences', methods=['GET', 'POST'])
def user_preferences(user_id):
    if 'token' in flask.request.args:
        token = flask.request.args.get('token')
        data = verify_token(token, salt='password', secret_key=flask.current_app.config['SECRET_KEY'])
        if data is not None:
            return reset_password()
        else:
            # es ist egal, ob eingeloggt oder nicht
            return confirm_email()
    elif flask_login.current_user.is_authenticated:
        if user_id != flask_login.current_user.id:
            return flask.abort(403)
        else:
            if not flask_login.login_fresh():
                # ensure only fresh sessions can edit preferences including passwords and api tokens
                return flask.redirect(flask.url_for('.refresh_sign_in', next=flask.url_for('.user_preferences', user_id=flask_login.current_user.id)))
            # user eingeloggt, change preferences möglich
            user = flask_login.current_user
            return change_preferences(user, user_id)
    else:
        return flask.current_app.login_manager.unauthorized()


def change_preferences(user, user_id):
    api_tokens = Authentication.query.filter(Authentication.user_id == user_id, Authentication.type == AuthenticationType.API_TOKEN).all()
    authentication_methods = Authentication.query.filter(Authentication.user_id == user_id, Authentication.type != AuthenticationType.API_TOKEN).all()
    authentication_method_ids = [authentication_method.id for authentication_method in authentication_methods]
    confirmed_authentication_methods = Authentication.query.filter(Authentication.user_id == user_id, Authentication.confirmed == sqlalchemy.sql.expression.true(), Authentication.type != AuthenticationType.API_TOKEN).count()
    change_user_form = ChangeUserForm()
    authentication_form = AuthenticationForm()
    authentication_method_form = AuthenticationMethodForm()
    authentication_password_form = AuthenticationPasswordForm()

    created_api_token = None
    create_api_token_form = CreateAPITokenForm()

    add_user_permissions_form = ObjectUserPermissionsForm()
    add_group_permissions_form = ObjectGroupPermissionsForm()
    add_project_permissions_form = ObjectProjectPermissionsForm()

    notification_mode_form = NotificationModeForm()

    other_settings_form = OtherSettingsForm()
    user_settings = get_user_settings(flask_login.current_user.id)

    user_permissions = get_default_permissions_for_users(creator_id=flask_login.current_user.id)
    group_permissions = get_default_permissions_for_groups(creator_id=flask_login.current_user.id)
    project_permissions = get_default_permissions_for_projects(creator_id=flask_login.current_user.id)
    public_permissions = Permissions.READ if default_is_public(creator_id=flask_login.current_user.id) else Permissions.NONE
    user_permission_form_data = []
    for user_id, permissions in user_permissions.items():
        if user_id is None:
            continue
        user_permission_form_data.append({'user_id': user_id, 'permissions': permissions.name.lower()})
    group_permission_form_data = []
    for group_id, permissions in group_permissions.items():
        if group_id is None:
            continue
        group_permission_form_data.append({'group_id': group_id, 'permissions': permissions.name.lower()})
    project_permission_form_data = []
    for project_id, permissions in project_permissions.items():
        if project_id is None:
            continue
        project_permission_form_data.append({'project_id': project_id, 'permissions': permissions.name.lower()})
    default_permissions_form = ObjectPermissionsForm(public_permissions=public_permissions.name.lower(), user_permissions=user_permission_form_data, group_permissions=group_permission_form_data, project_permissions=project_permission_form_data)

    users = get_users(exclude_hidden=True)
    users = [user for user in users if user.id not in user_permissions]
    groups = get_user_groups(flask_login.current_user.id)
    groups = [group for group in groups if group.id not in group_permissions]
    projects = get_user_projects(flask_login.current_user.id)
    projects = [project for project in projects if project.id not in project_permissions]

    if 'change' not in flask.request.form:
        if change_user_form.name.data is None or change_user_form.name.data == "":
            change_user_form.name.data = user.name
        if change_user_form.email.data is None or change_user_form.email.data == "":
            change_user_form.email.data = user.email

    if 'edit' in flask.request.form and flask.request.form['edit'] == 'Edit':
        if authentication_password_form.validate_on_submit() and authentication_password_form.id.data in authentication_method_ids:
            authentication_method_id = authentication_password_form.id.data
            try:
                change_password_in_authentication_method(authentication_method_id, authentication_password_form.password.data)
                flask.flash("Successfully updated your password.", 'success')
            except Exception as e:
                flask.flash("Failed to change password.", 'error')
                return flask.render_template('preferences.html', user=user, change_user_form=change_user_form,
                                             authentication_password_form=authentication_password_form,
                                             default_permissions_form=default_permissions_form,
                                             add_user_permissions_form=add_user_permissions_form,
                                             add_group_permissions_form=add_group_permissions_form,
                                             notification_mode_form=notification_mode_form,
                                             Permissions=Permissions,
                                             NotificationMode=NotificationMode,
                                             NotificationType=NotificationType,
                                             notification_modes=get_notification_modes(flask_login.current_user.id),
                                             user_settings=user_settings,
                                             other_settings_form=other_settings_form,
                                             get_user=get_user,
                                             users=users,
                                             groups=groups,
                                             get_group=get_group,
                                             user_permissions=user_permissions,
                                             group_permissions=group_permissions,
                                             public_permissions=public_permissions,
                                             authentication_method_form=authentication_method_form,
                                             authentication_form=authentication_form,
                                             create_api_token_form=create_api_token_form,
                                             confirmed_authentication_methods=confirmed_authentication_methods,
                                             authentications=authentication_methods, error=str(e), api_tokens=api_tokens)
            user_log.edit_user_preferences(user_id=user_id)
            return flask.redirect(flask.url_for('frontend.user_me_preferences'))
        else:
            flask.flash("Failed to change the password.", 'error')
    if 'change' in flask.request.form and flask.request.form['change'] == 'Change':
        if change_user_form.validate_on_submit():
            if change_user_form.name.data != user.name:
                u = user
                u.name = str(change_user_form.name.data)
                db.session.add(u)
                db.session.commit()
                user_log.edit_user_preferences(user_id=user_id)
                flask.flash("Successfully updated your user name.", 'success')
            if change_user_form.email.data != user.email:
                # send confirm link
                send_confirm_email(change_user_form.email.data, user.id, 'edit_profile')
                flask.flash("Please see your email to confirm this change.", 'success')
            return flask.redirect(flask.url_for('frontend.user_me_preferences'))
    if 'remove' in flask.request.form and flask.request.form['remove'] == 'Remove':
        authentication_method_id = authentication_method_form.id.data
        if authentication_method_form.validate_on_submit():
            try:
                remove_authentication_method(authentication_method_id)
                flask.flash("Successfully removed the authentication method.", 'success')
            except Exception as e:
                flask.flash("Failed to remove the authentication method.", 'error')
                return flask.render_template('preferences.html', user=user, change_user_form=change_user_form,
                                             authentication_password_form=authentication_password_form,
                                             default_permissions_form=default_permissions_form,
                                             add_user_permissions_form=add_user_permissions_form,
                                             add_group_permissions_form=add_group_permissions_form,
                                             notification_mode_form=notification_mode_form,
                                             Permissions=Permissions,
                                             NotificationMode=NotificationMode,
                                             NotificationType=NotificationType,
                                             notification_modes=get_notification_modes(flask_login.current_user.id),
                                             user_settings=user_settings,
                                             other_settings_form=other_settings_form,
                                             get_user=get_user,
                                             users=users,
                                             groups=groups,
                                             get_group=get_group,
                                             user_permissions=user_permissions,
                                             group_permissions=group_permissions,
                                             public_permissions=public_permissions,
                                             authentication_method_form=authentication_method_form,
                                             authentication_form=authentication_form,
                                             create_api_token_form=create_api_token_form,
                                             confirmed_authentication_methods=confirmed_authentication_methods,
                                             authentications=authentication_methods, error=str(e), api_tokens=api_tokens)
            user_log.edit_user_preferences(user_id=user_id)
            return flask.redirect(flask.url_for('frontend.user_me_preferences'))
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
                add_authentication_method(user_id, authentication_form.login.data, authentication_form.password.data, authentication_method)
                flask.flash("Successfully added the authentication method.", 'success')
            except Exception as e:
                flask.flash("Failed to add an authentication method.", 'error')
                return flask.render_template('preferences.html', user=user, change_user_form=change_user_form,
                                             authentication_password_form=authentication_password_form,
                                             default_permissions_form=default_permissions_form,
                                             add_user_permissions_form=add_user_permissions_form,
                                             add_group_permissions_form=add_group_permissions_form,
                                             notification_mode_form=notification_mode_form,
                                             Permissions=Permissions,
                                             NotificationMode=NotificationMode,
                                             NotificationType=NotificationType,
                                             notification_modes=get_notification_modes(flask_login.current_user.id),
                                             user_settings=user_settings,
                                             other_settings_form=other_settings_form,
                                             get_user=get_user,
                                             users=users,
                                             groups=groups,
                                             get_group=get_group,
                                             user_permissions=user_permissions,
                                             group_permissions=group_permissions,
                                             public_permissions=public_permissions,
                                             authentication_method_form=authentication_method_form,
                                             authentication_form=authentication_form,
                                             create_api_token_form=create_api_token_form,
                                             confirmed_authentication_methods=confirmed_authentication_methods,
                                             authentications=authentication_methods, error_add=str(e), api_tokens=api_tokens)
            authentication_methods = Authentication.query.filter(Authentication.user_id == user_id, Authentication.type != AuthenticationType.API_TOKEN).all()
        else:
            flask.flash("Failed to add an authentication method.", 'error')
    if 'create_api_token' in flask.request.form and create_api_token_form.validate_on_submit():
        created_api_token = secrets.token_hex(32)
        description = create_api_token_form.description.data
        try:
            add_api_token(flask_login.current_user.id, created_api_token, description)
            api_tokens = Authentication.query.filter(Authentication.user_id == user_id, Authentication.type == AuthenticationType.API_TOKEN).all()
        except Exception as e:
            flask.flash("Failed to add an API token.", 'error')
            return flask.render_template('preferences.html', user=user, change_user_form=change_user_form,
                                         authentication_password_form=authentication_password_form,
                                         default_permissions_form=default_permissions_form,
                                         add_user_permissions_form=add_user_permissions_form,
                                         add_group_permissions_form=add_group_permissions_form,
                                         notification_mode_form=notification_mode_form,
                                         Permissions=Permissions,
                                         NotificationMode=NotificationMode,
                                         NotificationType=NotificationType,
                                         notification_modes=get_notification_modes(flask_login.current_user.id),
                                         user_settings=user_settings,
                                         other_settings_form=other_settings_form,
                                         get_user=get_user,
                                         users=users,
                                         groups=groups,
                                         get_group=get_group,
                                         user_permissions=user_permissions,
                                         group_permissions=group_permissions,
                                         public_permissions=public_permissions,
                                         authentication_method_form=authentication_method_form,
                                         authentication_form=authentication_form,
                                         create_api_token_form=create_api_token_form,
                                         confirmed_authentication_methods=confirmed_authentication_methods,
                                         authentications=authentication_methods, error_add=str(e), api_tokens=api_tokens)
    if 'edit_user_permissions' in flask.request.form and default_permissions_form.validate_on_submit():
        set_default_public(creator_id=flask_login.current_user.id, is_public=(default_permissions_form.public_permissions.data == 'read'))
        for user_permissions_data in default_permissions_form.user_permissions.data:
            user_id = user_permissions_data['user_id']
            try:
                get_user(user_id)
            except UserDoesNotExistError:
                continue
            permissions = Permissions.from_name(user_permissions_data['permissions'])
            set_default_permissions_for_user(creator_id=flask_login.current_user.id, user_id=user_id, permissions=permissions)
        for group_permissions_data in default_permissions_form.group_permissions.data:
            group_id = group_permissions_data['group_id']
            try:
                get_group(group_id)
            except GroupDoesNotExistError:
                continue
            permissions = Permissions.from_name(group_permissions_data['permissions'])
            set_default_permissions_for_group(creator_id=flask_login.current_user.id, group_id=group_id, permissions=permissions)
        for project_permissions_data in default_permissions_form.project_permissions.data:
            project_id = project_permissions_data['project_id']
            try:
                get_project(project_id)
            except ProjectDoesNotExistError:
                continue
            permissions = Permissions.from_name(project_permissions_data['permissions'])
            set_default_permissions_for_project(creator_id=flask_login.current_user.id, project_id=project_id, permissions=permissions)
        flask.flash("Successfully updated default permissions.", 'success')
        return flask.redirect(flask.url_for('.user_preferences', user_id=flask_login.current_user.id))
    if 'add_user_permissions' in flask.request.form and add_user_permissions_form.validate_on_submit():
        user_id = add_user_permissions_form.user_id.data
        permissions = Permissions.from_name(add_user_permissions_form.permissions.data)
        default_user_permissions = get_default_permissions_for_users(creator_id=flask_login.current_user.id)
        assert permissions in [Permissions.READ, Permissions.WRITE, Permissions.GRANT]
        assert user_id not in default_user_permissions
        set_default_permissions_for_user(creator_id=flask_login.current_user.id, user_id=user_id, permissions=permissions)
        flask.flash("Successfully updated default permissions.", 'success')
        return flask.redirect(flask.url_for('.user_preferences', user_id=flask_login.current_user.id))
    if 'add_group_permissions' in flask.request.form and add_group_permissions_form.validate_on_submit():
        group_id = add_group_permissions_form.group_id.data
        permissions = Permissions.from_name(add_group_permissions_form.permissions.data)
        default_group_permissions = get_default_permissions_for_groups(creator_id=flask_login.current_user.id)
        assert permissions in [Permissions.READ, Permissions.WRITE, Permissions.GRANT]
        assert group_id not in default_group_permissions
        set_default_permissions_for_group(creator_id=flask_login.current_user.id, group_id=group_id, permissions=permissions)
        flask.flash("Successfully updated default permissions.", 'success')
        return flask.redirect(flask.url_for('.user_preferences', user_id=flask_login.current_user.id))
    if 'add_project_permissions' in flask.request.form and add_project_permissions_form.validate_on_submit():
        project_id = add_project_permissions_form.project_id.data
        permissions = Permissions.from_name(add_project_permissions_form.permissions.data)
        default_project_permissions = get_default_permissions_for_projects(creator_id=flask_login.current_user.id)
        assert permissions in [Permissions.READ, Permissions.WRITE, Permissions.GRANT]
        assert project_id not in default_project_permissions
        set_default_permissions_for_project(creator_id=flask_login.current_user.id, project_id=project_id, permissions=permissions)
        flask.flash("Successfully updated default permissions.", 'success')
        return flask.redirect(flask.url_for('.user_preferences', user_id=flask_login.current_user.id))
    if 'edit_notification_settings' in flask.request.form and notification_mode_form.validate_on_submit():
        for notification_type in NotificationType:
            if 'notification_mode_for_type_' + notification_type.name.lower() in flask.request.form:
                notification_mode_text = flask.request.form.get('notification_mode_for_type_' + notification_type.name.lower())
                for notification_mode in [NotificationMode.IGNORE, NotificationMode.WEBAPP, NotificationMode.EMAIL]:
                    if notification_mode_text == notification_mode.name.lower():
                        set_notification_mode_for_type(notification_type, flask_login.current_user.id, notification_mode)
                        break
        flask.flash("Successfully updated your notification settings.", 'success')
        return flask.redirect(flask.url_for('.user_preferences', user_id=flask_login.current_user.id))
    confirmed_authentication_methods = Authentication.query.filter(Authentication.user_id == user_id, Authentication.confirmed == sqlalchemy.sql.expression.true(), Authentication.type != AuthenticationType.API_TOKEN).count()
    if 'edit_other_settings' in flask.request.form and other_settings_form.validate_on_submit():
        use_schema_editor = flask.request.form.get('input-use-schema-editor', 'yes') != 'no'
        modified_settings = {
            'USE_SCHEMA_EDITOR': use_schema_editor
        }

        objects_per_page = flask.request.form.get('input-objects-per-page', '')
        if objects_per_page == 'all':
            modified_settings['OBJECTS_PER_PAGE'] = None
        else:
            try:
                modified_settings['OBJECTS_PER_PAGE'] = int(objects_per_page)
            except ValueError:
                pass

        set_user_settings(flask_login.current_user.id, modified_settings)
        flask.flash("Successfully updated your settings.", 'success')
        return flask.redirect(flask.url_for('.user_preferences', user_id=flask_login.current_user.id))
    return flask.render_template('preferences.html', user=user, change_user_form=change_user_form,
                                 authentication_password_form=authentication_password_form,
                                 default_permissions_form=default_permissions_form,
                                 add_user_permissions_form=add_user_permissions_form,
                                 add_group_permissions_form=add_group_permissions_form,
                                 add_project_permissions_form=add_project_permissions_form,
                                 notification_mode_form=notification_mode_form,
                                 NotificationMode=NotificationMode,
                                 NotificationType=NotificationType,
                                 notification_modes=get_notification_modes(flask_login.current_user.id),
                                 user_settings=user_settings,
                                 other_settings_form=other_settings_form,
                                 Permissions=Permissions,
                                 users=users,
                                 get_user=get_user,
                                 groups=groups,
                                 get_group=get_group,
                                 projects=projects,
                                 get_project=get_project,
                                 user_permissions=user_permissions,
                                 group_permissions=group_permissions,
                                 project_permissions=project_permissions,
                                 public_permissions=public_permissions,
                                 authentication_method_form=authentication_method_form,
                                 authentication_form=authentication_form,
                                 create_api_token_form=create_api_token_form,
                                 created_api_token=created_api_token,
                                 confirmed_authentication_methods=confirmed_authentication_methods,
                                 authentications=authentication_methods, api_tokens=api_tokens)


def confirm_email():
    token = flask.request.args.get('token')
    data1 = verify_token(token, salt='edit_profile', secret_key=flask.current_app.config['SECRET_KEY'])
    data2 = verify_token(token, salt='add_login', secret_key=flask.current_app.config['SECRET_KEY'])
    if data1 is None and data2 is None:
        return flask.abort(404)
    else:
        if data1 is not None:
            data = data1
            salt = 'edit_profile'
        if data2 is not None:
            data = data2
            salt = 'add_login'
        if len(data) != 2:
            return flask.abort(400)
        email = data[0]
        user_id = data[1]
        if salt == 'edit_profile':
            user = get_user(user_id)
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


def email_for_resetting_password():
    request_password_reset_form = RequestPasswordResetForm()
    if flask.request.method == "GET":
        #  GET (email dialog )
        return flask.render_template('reset_password_by_email.html',
                                     request_password_reset_form=request_password_reset_form)
    if flask.request.method == "POST":
        has_error = False
        if request_password_reset_form.validate_on_submit():
            email = request_password_reset_form.email.data
            if '@' not in email:
                has_error = True
            else:
                send_recovery_email(email)
                return flask.render_template('recovery_email_send.html',
                                             email=email, has_error=has_error)
        return flask.render_template('reset_password_by_email.html',
                                     request_password_reset_form=request_password_reset_form,
                                     has_error=has_error)


def reset_password():
    token = flask.request.args.get('token')
    authentication_id = verify_token(token, salt='password', secret_key=flask.current_app.config['SECRET_KEY'])
    if not authentication_id:
        return flask.abort(404)
    authentication_method = Authentication.query.filter(Authentication.id == authentication_id).first()
    password_form = PasswordForm()
    has_error = False
    if authentication_method is None:
        return flask.abort(404)
    username = authentication_method.login['login']
    if flask.request.method == "GET":
        # confirmation dialog
        return flask.render_template('password.html', password_form=password_form, has_error=has_error,
                                     user=authentication_method.user, username=username)
    else:
        if password_form.validate_on_submit():
            if change_password_in_authentication_method(authentication_method.id, password_form.password.data):
                flask.flash("Your password has been reset.", 'success')
            else:
                flask.flash("Resetting your password failed. Please try again or contact an administrator.", 'error')
            return flask.redirect(flask.url_for('frontend.index'))
        return flask.render_template('password.html', password_form=password_form, has_error=has_error,
                                     user=authentication_method.user, username=username)
