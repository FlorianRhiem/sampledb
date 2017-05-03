# coding: utf-8
"""
Object Permissions

There are three types of permissions for each object:
 - READ, being able to access all information on an object,
 - WRITE, being able to update an object, and
 - GRANT, being able to grant permissions to other users.

When an object is created, its creator initially gets GRANT permissions for the object. In addition, if the object
was created performing an instrument action, the instrument responsible users will have GRANT access rights, not as
individuals, but in their role of responsible users. So even when a user becomes responsible user AFTER an object was
created using an instrument, this user will then have GRANT rights, until he is removed from the list of responsible
users for the instrument.

Objects can be made public, which grants READ permissions to any logged-in user trying to access the object.
"""

import typing
from .. import db
from .instruments import get_action
from ..models import Permissions, UserObjectPermissions, PublicObjects, Objects, ActionType, Action, Object


__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'


def object_is_public(object_id):
    return PublicObjects.query.filter_by(object_id=object_id).first() is not None


def set_object_public(object_id, is_public=True):
    if not is_public:
        PublicObjects.query.filter_by(object_id=object_id).delete()
    elif not object_is_public(object_id):
        db.session.add(PublicObjects(object_id=object_id))
    db.session.commit()


def get_object_permissions(object_id, include_instrument_responsible_users=True):
    object_permissions = {}
    if object_is_public(object_id):
        object_permissions[None] = Permissions.READ
    else:
        object_permissions[None] = Permissions.NONE
    for user_object_permissions in UserObjectPermissions.query.filter_by(object_id=object_id).all():
        object_permissions[user_object_permissions.user_id] = user_object_permissions.permissions
    if include_instrument_responsible_users:
        for user_id in _get_object_responsible_user_ids(object_id):
            object_permissions[user_id] = Permissions.GRANT
    return object_permissions


def _get_object_responsible_user_ids(object_id):
    object = Objects.get_current_object(object_id, connection=db.engine)
    action = get_action(object.action_id)
    if action is None or action.instrument is None:
        return []
    return [user.id for user in action.instrument.responsible_users]


def get_user_object_permissions(object_id, user_id):
    assert user_id is not None
    # instrument responsible users always have GRANT permissions for an object
    if user_id in _get_object_responsible_user_ids(object_id):
        return Permissions.GRANT
    # other users might have been granted permissions
    user_object_permissions = UserObjectPermissions.query.filter_by(object_id=object_id, user_id=user_id).first()
    if user_object_permissions is not None and user_object_permissions.permissions != Permissions.NONE:
        return user_object_permissions.permissions
    # lastly, the object may be public, so all users have READ permissions
    if object_is_public(object_id):
        return Permissions.READ
    # otherwise the user has no permissions for this object
    return Permissions.NONE


def set_user_object_permissions(object_id, user_id, permissions: Permissions):
    assert user_id is not None
    if permissions == Permissions.NONE:
        UserObjectPermissions.query.filter_by(object_id=object_id, user_id=user_id).delete()
    else:
        user_object_permissions = UserObjectPermissions.query.filter_by(object_id=object_id, user_id=user_id).first()
        if user_object_permissions is None:
            user_object_permissions = UserObjectPermissions(user_id=user_id, object_id=object_id, permissions=permissions)
        else:
            user_object_permissions.permissions = permissions
        db.session.add(user_object_permissions)
    db.session.commit()


def set_initial_permissions(obj):
    set_user_object_permissions(object_id=obj.object_id, user_id=obj.user_id, permissions=Permissions.GRANT)
    # TODO: remove this for production use
    set_object_public(object_id=obj.object_id)

Objects.create_object_callbacks.append(set_initial_permissions)


def get_objects_with_permissions(user_id: int, permissions: Permissions, filter_func: typing.Callable=lambda data: True, action_id: int=None, action_type: ActionType=None) -> typing.List[Object]:
    action_table = Action.__table__
    if action_type is not None and action_id is not None:
        action_filter = db.and_(Action.type == action_type, Action.id == action_id)
    elif action_type is not None:
        action_filter = (Action.type == action_type)
    elif action_id is not None:
        action_filter = (Action.id == action_id)
    else:
        action_table = None
        action_filter = None

    objects = Objects.get_current_objects(filter_func=filter_func, action_table=action_table, action_filter=action_filter)
    objects = [obj for obj in objects if permissions in get_user_object_permissions(user_id=user_id, object_id=obj.object_id)]
    return objects
