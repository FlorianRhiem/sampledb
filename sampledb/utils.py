# coding: utf-8
"""

"""

import base64
import functools
import json
import os

import flask
import flask_login

from . import logic
from .models import Permissions

__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'


def object_permissions_required(required_object_permissions: Permissions):
    def decorator(func):
        @flask_login.login_required
        @functools.wraps(func)
        def wrapper(**kwargs):
            assert 'object_id' in kwargs
            object_id = kwargs['object_id']
            try:
                logic.objects.get_object(object_id)
            except logic.errors.ObjectDoesNotExistError:
                return flask.abort(404)
            if not logic.permissions.object_is_public(object_id):
                user_id = flask_login.current_user.id
                user_object_permissions = logic.permissions.get_user_object_permissions(object_id=object_id, user_id=user_id)
                if required_object_permissions not in user_object_permissions:
                    # TODO: handle lack of permissions better
                    return flask.abort(403)
            return func(**kwargs)
        return wrapper
    return decorator


def load_environment_configuration(env_prefix):
    """
    Loads configuration data from environment variables with a given prefix.
    If the prefixed environment variable B64_JSON_ENV exists, its content
    will be treated as an Base64 encoded JSON object and it's attributes
    starting with the prefix will be added to the environment.
    
    :return: a dict containing the configuration values
    """
    b64_json_env = os.environ.get(env_prefix + 'B64_JSON_ENV', None)
    if b64_json_env:
        for key, value in json.loads(base64.b64decode(b64_json_env.encode('utf-8')).decode('utf-8')).items():
            if key.startswith(env_prefix):
                os.environ[key] = value
    config = {
        key[len(env_prefix):]: value
        for key, value in os.environ.items()
        if key.startswith(env_prefix) and key != env_prefix + 'B64_JSON_ENV'
    }
    return config


def generate_secret_key(num_bits):
    """
    Generates a secure, random key for the application.
    
    :param num_bits: number of bits of random data in the secret key
    :return: the base64 encoded secret key
    """
    num_bytes = num_bits // 8
    binary_key = os.urandom(num_bytes)
    base64_key = base64.b64encode(binary_key).decode('ascii')
    return base64_key
