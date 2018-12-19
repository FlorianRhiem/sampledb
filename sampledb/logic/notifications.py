# coding: utf-8
"""

"""

import collections
import datetime
import typing
import smtplib

import flask
import flask_mail

from . import errors, users, objects, groups, projects
from ..models import notifications
from ..models.notifications import NotificationType, NotificationMode
from .. import db
from .. import mail


class Notification(collections.namedtuple('Notification', ['id', 'type', 'user_id', 'data', 'was_read', 'utc_datetime'])):
    """
    This class provides an immutable wrapper around models.notifications.Notification.
    """

    def __new__(cls, id: int, type: NotificationType, user_id: int, data: typing.Dict[str, typing.Any], was_read: bool, utc_datetime: typing.Optional[datetime.datetime]=None):
        self = super(Notification, cls).__new__(cls, id, type, user_id, data, was_read, utc_datetime)
        return self

    @classmethod
    def from_database(cls, notification: notifications.Notification) -> 'Notification':
        return Notification(
            id=notification.id,
            type=notification.type,
            user_id=notification.user_id,
            data=notification.data,
            was_read=notification.was_read,
            utc_datetime=notification.utc_datetime
        )


def get_notifications(user_id: int, unread_only: bool=False) -> typing.List[Notification]:
    """
    Get all (unread) notifications for a given user.

    :param user_id: the ID of an existing user
    :param unread_only: whether only unread notifications should be returned
    :return: a list of (unread) notifications
    :raise errors.UserDoesNotExistError: when no user with the given user ID
        exists
    """
    # ensure the user exists
    users.get_user(user_id)
    if unread_only:
        db_notifications = notifications.Notification.query.filter_by(user_id=user_id, was_read=False).order_by(notifications.Notification.utc_datetime.desc()).all()
    else:
        db_notifications = notifications.Notification.query.filter_by(user_id=user_id).order_by(notifications.Notification.utc_datetime.desc()).all()
    return [
        Notification.from_database(notification)
        for notification in db_notifications
    ]


def get_num_notifications(user_id: int, unread_only: bool=False) -> int:
    """
    Get the number of (unread) notifications for a given user.

    :param user_id: the ID of an existing user
    :param unread_only: whether only unread notifications should be returned
    :return: the number of (unread) notifications
    :raise errors.UserDoesNotExistError: when no user with the given user ID
        exists
    """
    # ensure the user exists
    users.get_user(user_id)
    if unread_only:
        return notifications.Notification.query.filter_by(user_id=user_id, was_read=False).count()
    else:
        return notifications.Notification.query.filter_by(user_id=user_id).count()


def get_notification(notification_id) -> Notification:
    """
    Get a specific notification.

    :param notification_id: the ID of an existing notification
    :return: a notification
    :raise errors.NotificationDoesNotExist: when no notification with the
        given notification ID exists
    """
    notification = notifications.Notification.query.filter_by(id=notification_id).first()
    if notification is None:
        raise errors.NotificationDoesNotExistError()
    return Notification.from_database(notification)


def _create_notification(type: NotificationType, user_id: int, data: typing.Dict[str, typing.Any]) -> None:
    """
    Create a new notification and handle it according to the user's settings.

    Use the convenience functions for creating specific notifications instead.

    :param type: the type of the new notification
    :param user_id: the ID of an existing user
    :param data: the data for the new notification
    :raise errors.UserDoesNotExistError: when no user with the given user ID
        exists
    """
    notification_mode = get_notification_mode_for_type(type, user_id)
    if notification_mode == NotificationMode.WEBAPP:
        _store_notification(type, user_id, data)
    if notification_mode == NotificationMode.EMAIL:
        _send_notification(type, user_id, data)


def _store_notification(type: NotificationType, user_id: int, data: typing.Dict[str, typing.Any]) -> None:
    """
    Store a new notification in the database.

    :param type: the type of the new notification
    :param user_id: the ID of an existing user
    :param data: the data for the new notification
    :raise errors.UserDoesNotExistError: when no user with the given user ID
        exists
    """
    # ensure the user exists
    users.get_user(user_id)
    notification = notifications.Notification(
        type=type,
        user_id=user_id,
        data=data,
        utc_datetime=datetime.datetime.utcnow()
    )
    db.session.add(notification)
    db.session.commit()


def _send_notification(type: NotificationType, user_id: int, data: typing.Dict[str, typing.Any]) -> None:
    """
    Send a new notification by email.

    :param type: the type of the new notification
    :param user_id: the ID of an existing user
    :param data: the data for the new notification
    :raise errors.UserDoesNotExistError: when no user with the given user ID
        exists
    """
    user = users.get_user(user_id)
    subject = "iffSamples Notification"

    if type == NotificationType.OTHER:
        template_path = 'mails/notifications/other'
    elif type == NotificationType.ASSIGNED_AS_RESPONSIBLE_USER:
        template_path = 'mails/notifications/assigned_as_responsible_user'
    elif type == NotificationType.INVITED_TO_GROUP:
        template_path = 'mails/notifications/invited_to_group'
    elif type == NotificationType.INVITED_TO_PROJECT:
        template_path = 'mails/notifications/invited_to_project'
    else:
        # unknown notification type
        return

    html = flask.render_template(template_path + '.html', user=user, type=type, data=data, get_user=users.get_user, get_group=groups.get_group, get_project=projects.get_project)
    text = flask.render_template(template_path + '.txt', user=user, type=type, data=data, get_user=users.get_user, get_group=groups.get_group, get_project=projects.get_project)
    while '\n\n\n' in text:
        text = text.replace('\n\n\n', '\n\n')
    try:
        mail.send(flask_mail.Message(
            subject,
            sender=flask.current_app.config['MAIL_SENDER'],
            recipients=[user.email],
            body=text,
            html=html
        ))
    except smtplib.SMTPRecipientsRefused:
        pass


def mark_notification_as_read(notification_id: int) -> None:
    """
    Mark a notification as having been read.

    :param notification_id: the ID of an existing notification
    :raise errors.NotificationDoesNotExist: when no notification with the
        given notification ID exists
    """
    notification = notifications.Notification.query.filter_by(id=notification_id).first()
    if notification is None:
        raise errors.NotificationDoesNotExistError()
    if not notification.was_read:
        notification.was_read = True
        db.session.add(notification)
        db.session.commit()


def delete_notification(notification_id: int) -> None:
    """
    Delete a notification.

    :param notification_id: the ID of an existing notification
    :raise errors.NotificationDoesNotExist: when no notification with the
        given notification ID exists
    """
    notification = notifications.Notification.query.filter_by(id=notification_id).first()
    if notification is None:
        raise errors.NotificationDoesNotExistError()
    db.session.delete(notification)
    db.session.commit()


def set_notification_mode_for_type(type: NotificationType, user_id: int, mode: NotificationMode) -> None:
    """
    Set the notification mode for a user for a specific notification type.

    :param type: the notification type to set the mode for
    :param user_id: the ID of an existing user
    :param mode: the notification mode to set for the type and user
    :raise errors.UserDoesNotExistError: when no user with the given user ID
        exists
    """
    # ensure the user exists
    users.get_user(user_id)
    notification_mode_for_type = notifications.NotificationModeForType.query.filter_by(type=type, user_id=user_id).first()
    if notification_mode_for_type is None:
        notification_mode_for_type = notifications.NotificationModeForType(type=type, user_id=user_id, mode=mode)
    else:
        notification_mode_for_type.mode = mode
    db.session.add(notification_mode_for_type)
    db.session.commit()


def set_notification_mode_for_all_types(user_id: int, mode: NotificationMode) -> None:
    """
    Set the notification mode for a user for all notification types.

    :param user_id: the ID of an existing user
    :param mode: the notification mode to set for the type and user
    :raise errors.UserDoesNotExistError: when no user with the given user ID
        exists
    """
    # ensure the user exists
    users.get_user(user_id)
    notification_mode_for_types = notifications.NotificationModeForType.query.filter_by(user_id=user_id).all()
    for notification_mode_for_type in notification_mode_for_types:
        db.session.delete(notification_mode_for_type)
    notification_mode_for_all_types = notifications.NotificationModeForType(type=None, user_id=user_id, mode=mode)
    db.session.add(notification_mode_for_all_types)
    db.session.commit()


def get_notification_mode_for_type(type: NotificationType, user_id: int) -> NotificationMode:
    """
    Get the notification mode for a user for a specific notification type.

    :param type: the notification type to get the mode for
    :param user_id: the ID of an existing user
    :raise errors.UserDoesNotExistError: when no user with the given user ID
        exists
    """
    # ensure the user exists
    users.get_user(user_id)
    notification_mode_for_type = notifications.NotificationModeForType.query.filter_by(type=type, user_id=user_id).first()
    if notification_mode_for_type is not None:
        return notification_mode_for_type.mode
    notification_mode_for_all_types = notifications.NotificationModeForType.query.filter_by(type=None, user_id=user_id).first()
    if notification_mode_for_all_types is not None:
        return notification_mode_for_all_types.mode
    return NotificationMode.WEBAPP


def get_notification_modes(user_id: int) -> typing.Dict[typing.Optional[NotificationType], NotificationMode]:
    """
    Get the notification modes for a user.

    :param user_id: the ID of an existing user
    :raise errors.UserDoesNotExistError: when no user with the given user ID
        exists
    """
    # ensure the user exists
    users.get_user(user_id)
    notification_modes = notifications.NotificationModeForType.query.filter_by(user_id=user_id).all()
    return {
        notification_mode_for_type.type: notification_mode_for_type.mode
        for notification_mode_for_type in notification_modes
    }


def create_other_notification(user_id: int, message: str) -> None:
    """
    Create a notification of type OTHER.

    :param user_id: the ID of an existing user
    :param message: the message for the notification
    :raise errors.UserDoesNotExistError: when no user with the given user ID
        exists
    """
    _create_notification(
        type=NotificationType.OTHER,
        user_id=user_id,
        data={
            'message': message
        }
    )


def create_notification_for_being_assigned_as_responsible_user(user_id: int, object_id: int, assigner_id: int) -> None:
    """
    Create a notification of type ASSIGNED_AS_RESPONSIBLE_USER.

    :param user_id: the ID of an existing user
    :param object_id: the ID of an existing object
    :param assigner_id: the ID of who assigned this user as responsible user
    :raise errors.UserDoesNotExistError: when no user with the given user ID
        or assigner ID exists
    :raise errors.ObjectDoesNotExistError: when no object with the given
        object ID exists
    """
    # ensure the object exists
    objects.get_object(object_id)
    # ensure the assigner exists
    users.get_user(assigner_id)
    _create_notification(
        type=NotificationType.ASSIGNED_AS_RESPONSIBLE_USER,
        user_id=user_id,
        data={
            'object_id': object_id,
            'assigner_id': assigner_id
        }
    )


def create_notification_for_being_invited_to_a_group(
        user_id: int,
        group_id: int,
        inviter_id: int,
        confirmation_url: str,
        expiration_utc_datetime: typing.Optional[datetime.datetime]
) -> None:
    """
    Create a notification of type INVITED_TO_GROUP.

    :param user_id: the ID of an existing user
    :param group_id: the ID of an existing group
    :param inviter_id: the ID of who invited this user to the group
    :param confirmation_url: the confirmation URL
    :param expiration_utc_datetime: the datetime when the confirmation URL expires (optional)
    :raise errors.UserDoesNotExistError: when no user with the given user ID
        or assigner ID exists
    :raise errors.GroupDoesNotExistError: when no group with the given group
        ID exists
    """
    # ensure the group exists
    groups.get_group(group_id)
    # ensure the inviter exists
    users.get_user(inviter_id)
    _create_notification(
        type=NotificationType.INVITED_TO_GROUP,
        user_id=user_id,
        data={
            'group_id': group_id,
            'inviter_id': inviter_id,
            'confirmation_url': confirmation_url,
            'expiration_utc_datetime': expiration_utc_datetime.strftime('%Y-%m-%d %H:%M:%S')
        }
    )


def create_notification_for_being_invited_to_a_project(
        user_id: int,
        project_id: int,
        inviter_id: int,
        confirmation_url: str,
        expiration_utc_datetime: typing.Optional[datetime.datetime]
) -> None:
    """
    Create a notification of type INVITED_TO_PROJECT.

    :param user_id: the ID of an existing user
    :param project_id: the ID of an existing project
    :param inviter_id: the ID of who invited this user to the project
    :param confirmation_url: the confirmation URL
    :param expiration_utc_datetime: the datetime when the confirmation URL expires (optional)
    :raise errors.UserDoesNotExistError: when no user with the given user ID
        or assigner ID exists
    :raise errors.ProjectDoesNotExistError: when no project with the given project
        ID exists
    """
    # ensure the project exists
    projects.get_project(project_id)
    # ensure the inviter exists
    users.get_user(inviter_id)
    _create_notification(
        type=NotificationType.INVITED_TO_PROJECT,
        user_id=user_id,
        data={
            'project_id': project_id,
            'inviter_id': inviter_id,
            'confirmation_url': confirmation_url,
            'expiration_utc_datetime': expiration_utc_datetime.strftime('%Y-%m-%d %H:%M:%S')
        }
    )
