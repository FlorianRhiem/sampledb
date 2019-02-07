# coding: utf-8
"""
Implementation of LDAP authentication.
"""

import ldap3
import flask

import typing

from . import errors
from . import users


def _get_user_dn_and_attributes(user_ldap_uid: str, attributes: typing.Sequence[str] = ()) -> typing.Optional[typing.Sequence[typing.Any]]:
    ldap_host = flask.current_app.config['LDAP_SERVER']
    user_base_dn = flask.current_app.config['LDAP_USER_BASE_DN']
    uid_filter = flask.current_app.config['LDAP_UID_FILTER']
    object_def = flask.current_app.config['LDAP_OBJECT_DEF']
    user_dn = flask.current_app.config['LDAP_USER_DN']
    password = flask.current_app.config['LDAP_PASSWORD']
    server = ldap3.Server(ldap_host, use_ssl=True, get_info=ldap3.ALL)
    try:
        connection = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
    except ldap3.LDAPBindError:
        return None
    object_def = ldap3.ObjectDef(object_def, connection)
    reader = ldap3.Reader(connection, object_def, user_base_dn, uid_filter.format(user_ldap_uid))
    reader.search(attributes)
    # search if uid matches exactly one user, not more
    if len(reader) != 1:
        return None
    user_attributes = [reader[0].entry_dn]
    for attribute in attributes:
        value = getattr(reader[0], attribute, None)
        if value:
            user_attributes.append(value[0])
        else:
            user_attributes.append(None)
    return user_attributes


def validate_user(user_ldap_uid: str, password: str) -> bool:
    """
    Return whether or not a user with this LDAP uid and password exists.

    This will return False if the uid is not unique, even if the password
    matches one of the users, to avoid conflicts.

    :param user_ldap_uid: the LDAP uid of a user
    :param password: the user's LDAP password
    :return: whether the user credentials are correct or not
    :raise errors.NoEmailInLDAPAccountError: when a user with the UID exists,
        but the LDAP_MAIL_ATTRIBUTE is not set for them
    """
    mail_attribute = flask.current_app.config['LDAP_MAIL_ATTRIBUTE']
    user = _get_user_dn_and_attributes(user_ldap_uid, [mail_attribute])
    if user is None:
        return False
    user_dn, mail = user
    if mail is None:
        raise errors.NoEmailInLDAPAccountError('Email in LDAP-account missing, please contact your administrator')
    ldap_host = flask.current_app.config['LDAP_SERVER']
    # try to bind with user credentials if a matching user exists
    server = ldap3.Server(ldap_host, use_ssl=True, get_info=ldap3.ALL)
    connection = ldap3.Connection(server, user=user_dn, password=password, raise_exceptions=False)
    return bool(connection.bind())


def create_user_from_ldap(user_ldap_uid: str) -> typing.Optional[users.User]:
    """
    Create a new user from LDAP information.

    The user's name is read from the LDAP_NAME_ATTRIBUTE, if the attribute
    is set, or the LDAP uid is used otherwise. Their email is read from the
    LDAP_MAIL_ATTRIBUTE.

    :param user_ldap_uid: the LDAP uid of a user
    :return: the newly created user or None, if information is missing.
    :raise errors.NoEmailInLDAPAccountError: when the LDAP_MAIL_ATTRIBUTE is
        not set for the user
    """
    name_attribute = flask.current_app.config['LDAP_NAME_ATTRIBUTE']
    mail_attribute = flask.current_app.config['LDAP_MAIL_ATTRIBUTE']
    user = _get_user_dn_and_attributes(
        user_ldap_uid,
        attributes=(name_attribute, mail_attribute)
    )
    if user is None:
        return None
    _, name, email = user
    if not email:
        raise errors.NoEmailInLDAPAccountError('There is no email set for your LDAP account. Please contact your administrator.')
    if not name:
        name = user_ldap_uid
    return users.create_user(
        name=name,
        email=email,
        type=users.UserType.PERSON
    )
