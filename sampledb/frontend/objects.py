# coding: utf-8
"""

"""

import datetime
import json
import flask
import flask_login
import itsdangerous

from . import frontend
from ..logic import user_log
from ..logic.permissions import get_user_object_permissions, object_is_public, get_object_permissions, set_object_public, set_user_object_permissions, get_objects_with_permissions
from ..logic.datatypes import JSONEncoder
from ..logic.schemas import validate, generate_placeholder, ValidationError
from ..logic.object_search import generate_filter_func
from .objects_forms import ObjectPermissionsForm, ObjectForm, ObjectVersionRestoreForm, ObjectUserPermissionsForm
from .. import db
from ..models import User, Action, Objects, Permissions, ActionType
from ..utils import object_permissions_required
from .utils import jinja_filter
from .object_form_parser import parse_form_data

__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'


@frontend.route('/objects/')
@flask_login.login_required
def objects():
    try:
        action_id = int(flask.request.args.get('action', ''))
    except ValueError:
        action_id = None
    action_type = flask.request.args.get('t', '')
    action_type = {
        'samples': ActionType.SAMPLE_CREATION,
        'measurements': ActionType.MEASUREMENT
    }.get(action_type, None)
    query_string = flask.request.args.get('q', '')
    filter_func = generate_filter_func(query_string)
    objects = get_objects_with_permissions(
        user_id=flask_login.current_user.id,
        permissions=Permissions.READ,
        filter_func=filter_func,
        action_id=action_id,
        action_type=action_type
    )

    for i, obj in enumerate(objects):
        if obj.version_id == 0:
            original_object = obj
        else:
            original_object = Objects.get_object_version(object_id=obj.object_id, version_id=0)
        objects[i] = {
            'object_id': obj.object_id,
            'version_id': obj.version_id,
            'created_by': User.query.get(original_object.user_id),
            'created_at': original_object.utc_datetime.strftime('%Y-%m-%d %H:%M:%S'),
            'modified_by': User.query.get(obj.user_id),
            'last_modified_at': obj.utc_datetime.strftime('%Y-%m-%d %H:%M:%S'),
            'data': obj.data,
            'schema': obj.schema,
            'action': Action.query.get(obj.action_id),
            'display_properties': {}
        }

    # TODO: select display_properties? nested display_properties? find common properties? use searched for properties?
    display_properties = ['substrate']
    for obj in objects:
        for property_name in display_properties:
            if property_name not in obj['data'] or '_type' not in obj['data'][property_name] or property_name not in obj['schema']['properties']:
                obj['display_properties'][property_name] = None
                continue
            obj['display_properties'][property_name] = (obj['data'][property_name], obj['schema']['properties'][property_name])

    display_property_titles = {}
    for property_name in display_properties:
        display_property_titles[property_name] = property_name
        possible_title = None
        title_is_shared = True
        for obj in objects:
            if obj['display_properties'][property_name] is None:
                continue
            if 'title' not in obj['display_properties'][property_name][1]:
                continue
            if possible_title is None:
                possible_title = obj['display_properties'][property_name][1]['title']
            elif possible_title != obj['display_properties'][property_name][1]['title']:
                title_is_shared = False
                break
        if title_is_shared and possible_title is not None:
            display_property_titles[property_name] = possible_title
    objects.sort(key=lambda obj: obj['object_id'])
    return flask.render_template('objects/objects.html', objects=objects, display_properties=display_properties, display_property_titles=display_property_titles, search_query=query_string, action_type=action_type, ActionType=ActionType)


@jinja_filter
def to_datatype(obj):
    return json.loads(json.dumps(obj), object_hook=JSONEncoder.object_hook)


def apply_action_to_data(data, schema, action, form_data):
    new_form_data = form_data
    if action.endswith('_delete'):
        id_prefix = action[len('action_object_'):-len('_delete')]
        deleted_item_index = int(id_prefix.split('_')[-1])
        parent_id_prefix = 'object_'+'_'.join(id_prefix.split('_')[:-1]) + '_'
        new_form_data = {}
        for name in form_data:
            if not name.startswith(parent_id_prefix):
                new_form_data[name] = form_data[name]
            else:
                item_index = int(name[len(parent_id_prefix):].split('_')[0])
                if item_index < deleted_item_index:
                    new_form_data[name] = form_data[name]
                if item_index > deleted_item_index:
                    new_name = parent_id_prefix + str(item_index-1) + name[len(parent_id_prefix+str(item_index)):]
                    new_form_data[new_name] = form_data[name]
    elif action.endswith('_add'):
        id_prefix = action[len('action_object_'):-len('_add')]
    else:
        raise ValueError('invalid action')
    keys = id_prefix.split('_')
    sub_data = data
    sub_schema = schema
    try:
        for key in keys[:-1]:
            if sub_schema['type'] == 'array':
                key = int(key)
                sub_schema = sub_schema['items']
            elif sub_schema['type'] == 'object':
                sub_schema = sub_schema['properties'][key]
            else:
                raise ValueError('invalid type')
            sub_data = sub_data[key]
        if sub_schema['type'] != 'array':
            raise ValueError('invalid type')
        if action.endswith('_delete'):
            if 'minItems' not in sub_schema or len(sub_data) > sub_schema["minItems"]:
                del sub_data[int(keys[-1])]
        elif action.endswith('_add'):
            if 'maxItems' not in sub_schema or len(sub_data) < sub_schema["maxItems"]:
                sub_data.append(generate_placeholder(sub_schema["items"]))
    except (ValueError, KeyError, IndexError, TypeError):
        # TODO: error handling/logging?
        raise ValueError('invalid action')
    return new_form_data


def show_object_form(object, action):
    if object is None:
        data = generate_placeholder(action.schema)
    else:
        data = object.data
    # TODO: update schema
    # schema = Action.query.get(object.action_id).schema
    if object is not None:
        schema = object.schema
    else:
        schema = action.schema
    action_id = action.id
    errors = []
    form_data = {}
    previous_actions = []
    serializer = itsdangerous.URLSafeSerializer(flask.current_app.config['SECRET_KEY'])
    form = ObjectForm()
    if flask.request.method != 'GET' and form.validate_on_submit():
        form_data = {k: v[0] for k, v in dict(flask.request.form).items()}

        if 'previous_actions' in flask.request.form:
            try:
                previous_actions = serializer.loads(flask.request.form['previous_actions'])
            except itsdangerous.BadData:
                flask.abort(400)

        if "action_submit" in form_data:
            object_data, errors = parse_form_data(dict(flask.request.form), schema)
            if object_data is not None  and not errors:
                try:
                    validate(object_data, schema)
                except ValidationError:
                    # TODO: proper logging
                    print('object schema validation failed')
                    # TODO: handle error
                    flask.abort(400)
                if object is None:
                    object = Objects.create_object(data=object_data, schema=schema, user_id=flask_login.current_user.id, action_id=action.id)
                    user_log.create_object(user_id=flask_login.current_user.id, object_id=object.object_id)
                    flask.flash('The object was created successfully.', 'success')
                else:
                    object = Objects.update_object(object_id=object.object_id, data=object_data, schema=schema, user_id=flask_login.current_user.id)
                    user_log.edit_object(user_id=flask_login.current_user.id, object_id=object.object_id, version_id=object.version_id)
                    flask.flash('The object was updated successfully.', 'success')
                return flask.redirect(flask.url_for('.object', object_id=object.object_id))
        elif any(name.startswith('action_object_') and (name.endswith('_delete') or name.endswith('_add')) for name in form_data):
            action = [name for name in form_data if name.startswith('action_')][0]
            previous_actions.append(action)
    for action in previous_actions:
        try:
            form_data = apply_action_to_data(data, schema, action, form_data)
        except ValueError:
            flask.abort(400)

    objects = get_objects_with_permissions(
        user_id=flask_login.current_user.id,
        permissions=Permissions.READ,
        action_type=ActionType.SAMPLE_CREATION
    )
    if object is None:
        return flask.render_template('objects/forms/form_create.html', action_id=action_id, schema=schema, data=data, errors=errors, form_data=form_data, previous_actions=serializer.dumps(previous_actions), form=form, objects=objects, datetime=datetime)
    else:
        return flask.render_template('objects/forms/form_edit.html', schema=schema, data=data, object_id=object.object_id, errors=errors, form_data=form_data, previous_actions=serializer.dumps(previous_actions), form=form, objects=objects, datetime=datetime)


@frontend.route('/objects/<int:object_id>', methods=['GET', 'POST'])
@object_permissions_required(Permissions.READ)
def object(object_id):
    object = Objects.get_current_object(object_id=object_id)

    user_permissions = get_user_object_permissions(object_id=object_id, user_id=flask_login.current_user.id)
    user_may_edit = Permissions.WRITE in user_permissions
    user_may_grant = Permissions.GRANT in user_permissions
    if not user_may_edit and flask.request.args.get('mode', '') == 'edit':
        return flask.abort(403)
    if flask.request.method == 'GET' and flask.request.args.get('mode', '') != 'edit':
        objects = get_objects_with_permissions(
            user_id=flask_login.current_user.id,
            permissions=Permissions.READ,
            action_type=ActionType.SAMPLE_CREATION
        )
        return flask.render_template('objects/view/base.html', schema=object.schema, data=object.data, last_edit_datetime=object.utc_datetime, last_edit_user=User.query.get(object.user_id), object_id=object_id, user_may_edit=user_may_edit, restore_form=None, version_id=object.version_id, user_may_grant=user_may_grant, objects=objects)

    return show_object_form(object, action=Action.query.get(object.action_id))


@frontend.route('/objects/new', methods=['GET', 'POST'])
@flask_login.login_required
def new_object():
    action_id = flask.request.args.get('action_id', None)
    if action_id is None or action_id == '':
        # TODO: handle error
        return flask.abort(404)
    action = Action.query.get(action_id)
    if action is None:
        # TODO: handle error
        return flask.abort(404)

    # TODO: check instrument permissions
    return show_object_form(None, action)


@frontend.route('/objects/<int:object_id>/versions/')
@object_permissions_required(Permissions.READ)
def object_versions(object_id):
    object = Objects.get_current_object(object_id=object_id)
    if object is None:
        return flask.abort(404)
    object_versions = Objects.get_object_versions(object_id=object_id)
    object_versions.sort(key=lambda object_version: -object_version.version_id)
    return flask.render_template('objects/object_versions.html', User=User, object=object, object_versions=object_versions)


@frontend.route('/objects/<int:object_id>/versions/<int:version_id>')
@object_permissions_required(Permissions.READ)
def object_version(object_id, version_id):
    object = Objects.get_object_version(object_id=object_id, version_id=version_id)
    form = None
    user_permissions = get_user_object_permissions(object_id=object_id, user_id=flask_login.current_user.id)
    if Permissions.WRITE in user_permissions:
        current_object = Objects.get_current_object(object_id=object_id)
        if current_object.version_id != version_id:
            form = ObjectVersionRestoreForm()
    user_may_grant = Permissions.GRANT in user_permissions

    return flask.render_template('objects/view/base.html', schema=object.schema, data=object.data, last_edit_datetime=object.utc_datetime, last_edit_user=User.query.get(object.user_id), object_id=object_id, version_id=version_id, restore_form=form, user_may_grant=user_may_grant)


@frontend.route('/objects/<int:object_id>/versions/<int:version_id>/restore', methods=['GET', 'POST'])
@object_permissions_required(Permissions.WRITE)
def restore_object_version(object_id, version_id):
    object_version = Objects.get_object_version(object_id=object_id, version_id=version_id)
    if object_version is None:
        return flask.abort(404)
    current_object = Objects.get_current_object(object_id=object_id)
    if current_object.version_id == version_id:
        return flask.abort(404)
    form = ObjectVersionRestoreForm()
    if form.validate_on_submit():
        Objects.restore_object_version(object_id=object_id, version_id=version_id, user_id=flask_login.current_user.id)
        user_log.edit_object(user_id=flask_login.current_user.id, object_id=object_id, version_id=current_object.version_id+1)
        return flask.redirect(flask.url_for('.object', object_id=object_id))
    return flask.render_template('objects/restore_object_version.html', object_id=object_id, version_id=version_id, restore_form=form)


@frontend.route('/objects/<int:object_id>/permissions')
@object_permissions_required(Permissions.READ)
def object_permissions(object_id):
    object = Objects.get_current_object(object_id, connection=db.engine)
    action = Action.query.get(object.action_id)
    instrument = action.instrument
    object_permissions = get_object_permissions(object_id=object_id, include_instrument_responsible_users=False)
    if Permissions.GRANT in get_user_object_permissions(object_id=object_id, user_id=flask_login.current_user.id):
        public_permissions = 'none'
        if Permissions.READ in object_permissions[None]:
            public_permissions = 'read'
        user_permissions = []
        for user_id, permissions in object_permissions.items():
            if user_id is None:
                continue
            user_permissions.append({'user_id': user_id, 'permissions': permissions.name.lower()})
        edit_user_permissions_form = ObjectPermissionsForm(public_permissions=public_permissions, user_permissions=user_permissions)
        users = User.query.all()
        users = [user for user in users if user.id not in object_permissions]
        add_user_permissions_form = ObjectUserPermissionsForm()
    else:
        edit_user_permissions_form = None
        add_user_permissions_form = None
        users = []
    return flask.render_template('objects/object_permissions.html', instrument=instrument, action=action, object=object, object_permissions=object_permissions, User=User, Permissions=Permissions, form=edit_user_permissions_form, users=users, add_user_permissions_form=add_user_permissions_form)


@frontend.route('/objects/<int:object_id>/permissions', methods=['POST'])
@object_permissions_required(Permissions.GRANT)
def update_object_permissions(object_id):

    edit_user_permissions_form = ObjectPermissionsForm()
    add_user_permissions_form = ObjectUserPermissionsForm()
    if 'edit_user_permissions' in flask.request.form and edit_user_permissions_form.validate_on_submit():
        set_object_public(object_id, edit_user_permissions_form.public_permissions.data == 'read')
        for user_permissions_data in edit_user_permissions_form.user_permissions.data:
            user_id = user_permissions_data['user_id']
            user = User.query.get(user_id)
            if user is None:
                continue
            permissions = Permissions.from_name(user_permissions_data['permissions'])
            set_user_object_permissions(object_id=object_id, user_id=user_id, permissions=permissions)
        user_log.edit_object_permissions(user_id=flask_login.current_user.id, object_id=object_id)
        flask.flash("Successfully updated object permissions.", 'success')
    elif 'add_user_permissions' in flask.request.form and add_user_permissions_form.validate_on_submit():
        user_id = add_user_permissions_form.user_id.data
        permissions = Permissions.from_name(add_user_permissions_form.permissions.data)
        object_permissions = get_object_permissions(object_id=object_id, include_instrument_responsible_users=False)
        assert permissions in [Permissions.READ, Permissions.WRITE, Permissions.GRANT]
        assert user_id not in object_permissions
        user_log.edit_object_permissions(user_id=flask_login.current_user.id, object_id=object_id)
        set_user_object_permissions(object_id=object_id, user_id=user_id, permissions=permissions)
        flask.flash("Successfully updated object permissions.", 'success')
    else:
        flask.flash("A problem occurred while changing the object permissions. Please try again.", 'error')
    return flask.redirect(flask.url_for('.object_permissions', object_id=object_id))
