# coding: utf-8
"""

"""

from . import actions
from . import api_log
from . import authentication
from . import comments
from . import datatypes
from . import errors
from . import favorites
from . import files
from . import groups
from . import instruments
from . import ldap
from . import locations
from . import notifications
from . import objects
from . import object_log
from . import object_relationships
from . import object_search
from . import object_permissions
from . import object_sorting
from . import projects
from . import publications
from . import schemas
from . import security_tokens
from . import settings
from . import tags
from . import units
from . import users
from . import user_log
from . import utils
from . import where_filters

from ..models.objects import Objects

__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'


__all__ = [
    'actions',
    'api_log',
    'authentication',
    'comments',
    'datatypes',
    'errors',
    'favorites',
    'files',
    'groups',
    'instruments',
    'ldap',
    'locations',
    'notifications',
    'objects',
    'object_log',
    'object_relationships',
    'object_search',
    'object_permissions',
    'object_sorting',
    'projects',
    'publications',
    'security_tokens',
    'settings',
    'tags',
    'units',
    'users',
    'user_log',
    'utils',
    'where_filters',
]

Objects._data_validator = schemas.validate
Objects._schema_validator = schemas.validate_schema
