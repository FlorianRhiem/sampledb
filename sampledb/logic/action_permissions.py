# coding: utf-8
"""

"""

import typing
from .. import db
from . import errors
from . import actions
from . import groups
from . import users
from . import projects
from . import instruments
from ..models import Permissions, UserActionPermissions, GroupActionPermissions, ProjectActionPermissions, PublicActions, Action, ActionType

__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'


def action_is_public(action_id: int) -> bool:
    """
    Return whether an action is public or not.

    :param action_id: the ID of an existing action
    :return: whether the action is public or not
    :raise errors.ActionDoesNotExistError: if no action with the given action
        ID exists
    """
    # ensure that the action can be found
    action = actions.get_action(action_id)
    # common actions are always public
    if action.user_id is None:
        return True
    return PublicActions.query.filter_by(action_id=action_id).first() is not None


def set_action_public(action_id: int, is_public: bool = True) -> None:
    """
    Set that in action is public or not.

    :param action_id: the ID of an existing action
    :param is_public: whether the action should be public or not
    :raise errors.ActionDoesNotExistError: if no action with the given action
        ID exists
    """
    # ensure that the action can be found
    actions.get_action(action_id)
    if not is_public:
        PublicActions.query.filter_by(action_id=action_id).delete()
    elif not action_is_public(action_id):
        db.session.add(PublicActions(action_id=action_id))
    db.session.commit()


def get_action_permissions_for_users(action_id, include_instrument_responsible_users=True, include_groups=True, include_projects=True) -> typing.Dict[int, Permissions]:
    """
    Get permissions for users for a specific action.

    :param action_id: the ID of an existing action
    :param include_instrument_responsible_users: whether instrument responsible user status should be included
    :param include_groups: whether groups that the users are members of should be included
    :param include_projects: whether projects that the users are members of should be included
    :return: a dict mapping users IDs to permissions
    :raise errors.ActionDoesNotExistError: if no action with the given action
        ID exists
    """
    # ensure that the action can be found
    action = actions.get_action(action_id)
    action_permissions = {}
    for user_action_permissions in UserActionPermissions.query.filter_by(action_id=action_id).all():
        action_permissions[user_action_permissions.user_id] = user_action_permissions.permissions
    if include_instrument_responsible_users:
        for user_id in _get_action_responsible_user_ids(action_id):
            action_permissions[user_id] = Permissions.GRANT
    if include_groups:
        for group_action_permissions in GroupActionPermissions.query.filter_by(action_id=action_id).all():
            for user_id in groups.get_group_member_ids(group_action_permissions.group_id):
                if user_id not in action_permissions or action_permissions[user_id] in group_action_permissions.permissions:
                    action_permissions[user_id] = group_action_permissions.permissions
    if include_projects:
        for project_action_permissions in ProjectActionPermissions.query.filter_by(action_id=action_id).all():
            for user_id, permissions in projects.get_project_member_user_ids_and_permissions(project_action_permissions.project_id, include_groups=include_groups).items():
                permissions = min(permissions, project_action_permissions.permissions)
                previous_permissions = action_permissions.get(user_id, Permissions.NONE)
                action_permissions[user_id] = max(previous_permissions, permissions)
    if action.user_id is not None:
        action_permissions[action.user_id] = Permissions.GRANT
    for user_id in action_permissions:
        user = users.get_user(user_id)
        if user.is_readonly:
            action_permissions[user_id] = min(action_permissions[user_id], Permissions.READ)
    return action_permissions


def _get_action_responsible_user_ids(action_id: int) -> typing.List[int]:
    try:
        action = actions.get_action(action_id)
    except errors.ActionDoesNotExistError:
        return []
    if action.instrument_id is None:
        return []
    instrument = instruments.get_instrument(action.instrument_id)
    return [user.id for user in instrument.responsible_users]


def get_action_permissions_for_groups(action_id: int, include_projects=False) -> typing.Dict[int, Permissions]:
    """
    Get permissions for a specific action for groups.

    :param action_id: the ID of an existing action
    :param include_projects: whether projects that the groups are members of should be included
    :return: a dict mapping group IDs to permissions
    :raise errors.ActionDoesNotExistError: if no action with the given action
        ID exists
    """
    # ensure that the action can be found
    actions.get_action(action_id)
    action_permissions = {}
    for group_action_permissions in GroupActionPermissions.query.filter_by(action_id=action_id).all():
        if group_action_permissions.permissions != Permissions.NONE:
            action_permissions[group_action_permissions.group_id] = group_action_permissions.permissions
    if include_projects:
        for project_action_permissions in ProjectActionPermissions.query.filter_by(action_id=action_id).all():
            for group_id, permissions in projects.get_project_member_group_ids_and_permissions(project_action_permissions.project_id).items():
                permissions = min(permissions, project_action_permissions.permissions)
                previous_permissions = action_permissions.get(group_id, Permissions.NONE)
                action_permissions[group_id] = max(previous_permissions, permissions)
    return action_permissions


def get_action_permissions_for_projects(action_id: int) -> typing.Dict[int, Permissions]:
    """
    Get permissions for a specific action for projects.

    :param action_id: the ID of an existing action
    :return: a dict mapping project IDs to permissions
    :raise errors.ActionDoesNotExistError: if no action with the given action
        ID exists
    """
    # ensure that the action can be found
    actions.get_action(action_id)
    action_permissions = {}
    for project_action_permissions in ProjectActionPermissions.query.filter_by(action_id=action_id).all():
        if project_action_permissions.permissions != Permissions.NONE:
            action_permissions[project_action_permissions.project_id] = project_action_permissions.permissions
    return action_permissions


def get_user_action_permissions(action_id, user_id, include_instrument_responsible_users: bool = True, include_groups: bool = True, include_projects: bool = True) -> Permissions:
    """
    Get permissions for a specific action for a specific user.

    :param action_id: the ID of an existing action
    :param user_id: the ID of an existing user
    :param include_instrument_responsible_users: whether instrument responsible user status should be included
    :param include_groups: whether groups that the users are members of should be included
    :param include_projects: whether projects that the users are members of should be included
    :return: the user's permissions for this action
    :raise errors.ActionDoesNotExistError: if no action with the given action
        ID exists
    :raise errors.UserDoesNotExistError: if no user with the given user ID
        exists
    """
    # ensure that the action can be found
    action = actions.get_action(action_id)
    # ensure that the user can be found
    user = users.get_user(user_id)

    if user.is_readonly:
        max_permissions = Permissions.READ
    else:
        max_permissions = Permissions.GRANT

    # administrators always have GRANT permissions
    if user.is_admin:
        return min(Permissions.GRANT, max_permissions)
    # action owners always have GRANT permissions
    if action.user_id == user_id:
        return min(Permissions.GRANT, max_permissions)
    if include_instrument_responsible_users:
        # instrument responsible users always have GRANT permissions for an action
        if user_id in _get_action_responsible_user_ids(action_id):
            return min(Permissions.GRANT, max_permissions)
    # other users might have been granted permissions, either individually or as group or project members
    user_action_permissions = UserActionPermissions.query.filter_by(action_id=action_id, user_id=user_id).first()
    if user_action_permissions is None:
        permissions = Permissions.NONE
    else:
        permissions = user_action_permissions.permissions
    if Permissions.GRANT in permissions:
        return min(permissions, max_permissions)
    if include_groups:
        for group in groups.get_user_groups(user_id):
            group_action_permissions = GroupActionPermissions.query.filter_by(action_id=action_id, group_id=group.id).first()
            if group_action_permissions is not None and permissions in group_action_permissions.permissions:
                permissions = group_action_permissions.permissions
    if Permissions.GRANT in permissions:
        return min(permissions, max_permissions)
    if include_projects:
        for user_project in projects.get_user_projects(user_id, include_groups=include_groups):
            user_project_permissions = projects.get_user_project_permissions(user_project.id, user_id, include_groups=include_groups)
            if user_project_permissions not in permissions:
                project_action_permissions = ProjectActionPermissions.query.filter_by(action_id=action_id, project_id=user_project.id).first()
                if project_action_permissions is not None:
                    permissions = min(user_project_permissions, project_action_permissions.permissions)
    if Permissions.READ in permissions:
        return min(permissions, max_permissions)
    # lastly, the action may be public, so all users have READ permissions
    if action_is_public(action_id):
        return min(Permissions.READ, max_permissions)
    # otherwise the user has no permissions for this action
    return Permissions.NONE


def set_user_action_permissions(action_id: int, user_id: int, permissions: Permissions):
    """
    Set the action permissions for a user.

    Clear the permissions if called with Permissions.NONE

    :param action_id: the ID of an existing action
    :param user_id: the ID of an existing user
    :param permissions: the new permissions
    :raise errors.ActionDoesNotExistError: if no action with the given action
        ID exists
    :raise errors.UserDoesNotExistError: if no user with the given user ID
        exists
    """
    # ensure that the action can be found
    actions.get_action(action_id)
    # ensure that the user can be found
    users.get_user(user_id)
    if permissions == Permissions.NONE:
        UserActionPermissions.query.filter_by(action_id=action_id, user_id=user_id).delete()
    else:
        user_action_permissions = UserActionPermissions.query.filter_by(action_id=action_id, user_id=user_id).first()
        if user_action_permissions is None:
            user_action_permissions = UserActionPermissions(user_id=user_id, action_id=action_id, permissions=permissions)
        else:
            user_action_permissions.permissions = permissions
        db.session.add(user_action_permissions)
    db.session.commit()


def set_group_action_permissions(action_id: int, group_id: int, permissions: Permissions):
    """
    Set the action permissions for a group.

    Clear the permissions if called with Permissions.NONE

    :param action_id: the ID of an existing action
    :param group_id: the ID of an existing group
    :param permissions: the new permissions
    :raise errors.ActionDoesNotExistError: if no action with the given action
        ID exists
    :raise errors.GroupDoesNotExistError: if no group with the given group ID
        exists
    """
    # ensure that the action can be found
    actions.get_action(action_id)
    # ensure that the group can be found
    groups.get_group(group_id)
    if permissions == Permissions.NONE:
        GroupActionPermissions.query.filter_by(action_id=action_id, group_id=group_id).delete()
    else:
        group_action_permissions = GroupActionPermissions.query.filter_by(action_id=action_id, group_id=group_id).first()
        if group_action_permissions is None:
            group_action_permissions = GroupActionPermissions(action_id=action_id, group_id=group_id, permissions=permissions)
        else:
            group_action_permissions.permissions = permissions
        db.session.add(group_action_permissions)
    db.session.commit()


def set_project_action_permissions(action_id: int, project_id: int, permissions: Permissions) -> None:
    """
    Set the action permissions for a group.

    Clear the permissions if called with Permissions.NONE.

    :param action_id: the ID of an existing action
    :param group_id: the ID of an existing group
    :param permissions: the new permissions
    :raise errors.ActionDoesNotExistError: if no action with the given action
        ID exists
    :raise errors.ProjectDoesNotExistError: if no project with the given
        project ID exists
    """
    # ensure that the action can be found
    actions.get_action(action_id)
    # ensure that the project can be found
    projects.get_project(project_id)
    if permissions == Permissions.NONE:
        ProjectActionPermissions.query.filter_by(action_id=action_id, project_id=project_id).delete()
    else:
        project_action_permissions = ProjectActionPermissions.query.filter_by(action_id=action_id, project_id=project_id).first()
        if project_action_permissions is None:
            project_action_permissions = ProjectActionPermissions(project_id=project_id, action_id=action_id, permissions=permissions)
        else:
            project_action_permissions.permissions = permissions
        db.session.add(project_action_permissions)
    db.session.commit()


def get_actions_with_permissions(user_id: int, permissions: Permissions, action_type: typing.Optional[ActionType] = None) -> typing.List[Action]:
    """
    Get all actions which a user has the given permissions for.

    Return an empty list if called with Permissions.NONE.

    :param user_id: the ID of an existing user
    :param permissions: the minimum permissions required for the actions for
        the given user
    :param action_type: the type of action to filter for
    :return: the actions with the given permissions for the given
        user
    :raise errors.UserDoesNotExistError: if no user with the given user ID
        exists
    """
    # ensure that the user can be found
    users.get_user(user_id)
    if permissions == Permissions.NONE:
        return []
    actions_with_permissions = []
    for action in actions.get_actions(action_type):
        if permissions in get_user_action_permissions(user_id=user_id, action_id=action.id):
            actions_with_permissions.append(action)
    return actions_with_permissions
