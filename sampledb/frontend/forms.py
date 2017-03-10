# coding: utf-8
"""

"""

from flask_wtf import FlaskForm
from wtforms import FieldList, FormField, SelectField, IntegerField
from wtforms.validators import InputRequired
from ..permissions.models import Permissions

__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'


class ObjectUserPermissionsForm(FlaskForm):
    user_id = IntegerField(
        validators=[InputRequired()]
    )
    permissions = SelectField(
        choices=[(p.name.lower(), p.name.lower()) for p in (Permissions.NONE, Permissions.READ, Permissions.WRITE, Permissions.GRANT)],
        validators=[InputRequired()]
    )


class ObjectPermissionsForm(FlaskForm):
    public_permissions = SelectField(
        choices=[(p.name.lower(), p.name.lower()) for p in (Permissions.NONE, Permissions.READ)],
        validators=[InputRequired()]
    )
    user_permissions = FieldList(FormField(ObjectUserPermissionsForm), min_entries=0)
