# coding: utf-8
"""

"""

import flask
import flask_login

from .. import frontend
from ... import logic
from ...models import User
from .forms import InviteUserForm, EditGroupForm, LeaveGroupForm, CreateGroupForm


@frontend.route('/users/me/groups')
@flask_login.login_required
def current_user_groups():
    return flask.redirect(flask.url_for('.user_groups', user_id=flask_login.current_user.id))


@frontend.route('/users/<int:user_id>/groups', methods=['GET', 'POST'])
@flask_login.login_required
def user_groups(user_id):
    if user_id != flask_login.current_user.id and not flask_login.current_user.is_admin:
        return flask.abort(403)
    groups = logic.groups.get_user_groups(user_id)
    create_group_form = CreateGroupForm()
    if create_group_form.name.data is None:
        create_group_form.name.data = ''
    if create_group_form.description.data is None:
        create_group_form.description.data = ''
    show_create_form = False
    if 'create' in flask.request.form:
        show_create_form = True
        if create_group_form.validate_on_submit():
            try:
                group_id = logic.groups.create_group(create_group_form.name.data, create_group_form.description.data, flask_login.current_user.id)
            except logic.groups.GroupAlreadyExistsError:
                create_group_form.name.errors.append('A group with this name already exists.')
            except logic.groups.InvalidGroupNameError:
                create_group_form.name.errors.append('This group name is invalid.')
            else:
                flask.flash('The group has been created successfully.', 'success')
                return flask.redirect(flask.url_for('.group', group_id=group_id))
    return flask.render_template("groups.html", groups=groups, create_group_form=create_group_form, show_create_form=show_create_form)


@frontend.route('/groups/')
@flask_login.login_required
def groups():
    return flask.redirect(flask.url_for('.user_groups', user_id=flask_login.current_user.id))


@frontend.route('/groups/<int:group_id>', methods=['GET', 'POST'])
@flask_login.login_required
def group(group_id):
    try:
        group_member_ids = logic.groups.get_group_member_ids(group_id)
    except logic.groups.GroupDoesNotExistError:
        return flask.abort(404)
    if flask_login.current_user.id not in group_member_ids:
        return flask.abort(403)
    group = logic.groups.get_group(group_id)

    leave_group_form = LeaveGroupForm()
    invite_user_form = InviteUserForm()
    edit_group_form = EditGroupForm()
    if edit_group_form.name.data is None:
        edit_group_form.name.data = group.name
    if edit_group_form.description.data is None:
        edit_group_form.description.data = group.description

    show_edit_form = False
    if 'edit' in flask.request.form:
        show_edit_form = True
        if edit_group_form.validate_on_submit():
            try:
                logic.groups.update_group(group_id, edit_group_form.name.data, edit_group_form.description.data)
            except logic.groups.GroupDoesNotExistError:
                flask.flash('This group does not exist.', 'error')
                return flask.redirect(flask.url_for('.groups'))
            except logic.groups.GroupAlreadyExistsError:
                edit_group_form.name.errors.append('A group with this name already exists.')
            except logic.groups.InvalidGroupNameError:
                edit_group_form.name.errors.append('This group name is invalid.')
            else:
                flask.flash('Group information updated successfully.', 'success')
                return flask.redirect(flask.url_for('.group', group_id=group_id))
    elif 'add_user' in flask.request.form:
        if invite_user_form.validate_on_submit():
            try:
                # TODO: invitation instead of simple adding
                logic.groups.add_user_to_group(group_id, invite_user_form.user_id.data)
            except logic.groups.GroupDoesNotExistError:
                flask.flash('This group does not exist.', 'error')
                return flask.redirect(flask.url_for('.groups'))
            except logic.groups.UserDoesNotExistError:
                flask.flash('This user does not exist.', 'error')
            except logic.groups.UserAlreadyMemberOfGroupError:
                flask.flash('This user is already a member of this group', 'error')
            else:
                flask.flash('The user was successfully added to the group.', 'success')
                return flask.redirect(flask.url_for('.group', group_id=group_id))
    elif 'leave' in flask.request.form:
        if leave_group_form.validate_on_submit():
            try:
                logic.groups.remove_user_from_group(group_id, flask_login.current_user.id)
            except logic.groups.GroupDoesNotExistError:
                flask.flash('This group does not exist.', 'error')
                return flask.redirect(flask.url_for('.groups'))
            except logic.groups.UserDoesNotExistError:
                return flask.abort(500)
            except logic.groups.UserNotMemberOfGroupError:
                flask.flash('You have already left the group.', 'error')
                return flask.redirect(flask.url_for('.groups'))
            else:
                flask.flash('You have successfully left the group.', 'success')
                return flask.redirect(flask.url_for('.groups'))

    return flask.render_template('group.html', group=group, group_member_ids=group_member_ids, User=User, leave_group_form=leave_group_form, edit_group_form=edit_group_form, invite_user_form=invite_user_form, show_edit_form=show_edit_form)
