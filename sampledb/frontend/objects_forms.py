# coding: utf-8
"""

"""

from flask_wtf import FlaskForm
from wtforms import FieldList, FormField, SelectField, IntegerField, TextAreaField, HiddenField, FileField, StringField
from wtforms.validators import InputRequired, ValidationError

from ..logic.permissions import Permissions


class ObjectUserPermissionsForm(FlaskForm):
    user_id = IntegerField(
        validators=[InputRequired()]
    )
    permissions = SelectField(
        choices=[(p.name.lower(), p.name.lower()) for p in (Permissions.NONE, Permissions.READ, Permissions.WRITE, Permissions.GRANT)],
        validators=[InputRequired()]
    )


class ObjectGroupPermissionsForm(FlaskForm):
    group_id = IntegerField(
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
    group_permissions = FieldList(FormField(ObjectGroupPermissionsForm), min_entries=0)


class ObjectForm(FlaskForm):
    pass


class ObjectVersionRestoreForm(FlaskForm):
    pass


class CommentForm(FlaskForm):
    content = TextAreaField(validators=[InputRequired()])


class FileForm(FlaskForm):
    file_source = HiddenField(validators=[InputRequired()])
    file_names = HiddenField()
    local_files = FileField()

    def validate_file_source(form, field):
        if field.data not in ['local', 'instrument', 'jupyterhub']:
            raise ValidationError('Invalid file source')


class FileInformationForm(FlaskForm):
    title = StringField()
    description = TextAreaField()
