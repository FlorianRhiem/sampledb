# coding: utf-8
"""

"""


import datetime
import json
import jsonschema
import logging
import pytest
import requests
import flask_login
import sampledb
import sampledb.object_database.models
from sampledb.authentication import User, UserType
from sampledb.object_database import datatypes
from sampledb.object_database import views

from .utils import flask_server

logging.getLogger('werkzeug').setLevel(logging.WARNING)


__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'


@pytest.fixture
def app():
    sampledb_app = sampledb.create_app()

    @sampledb_app.route('/users/<int:user_id>/autologin')
    def autologin(user_id):
        user = User.query.get(user_id)
        assert user is not None
        flask_login.login_user(user)
        return ''

    db_url = sampledb_app.config['SQLALCHEMY_DATABASE_URI']
    engine = sampledb.db.create_engine(
        db_url,
        json_serializer=lambda obj: json.dumps(obj, cls=datatypes.JSONEncoder),
        json_deserializer=lambda obj: json.loads(obj, object_hook=datatypes.JSONEncoder.object_hook)
    )

    # fully empty the database first
    sampledb.db.MetaData(reflect=True, bind=engine).drop_all()
    # recreate the tables used by this application
    with sampledb_app.app_context():
        sampledb.db.metadata.create_all(bind=engine)
        sampledb.object_database.models.Objects.bind = sampledb.db.engine
        # create the object tables
        sampledb.object_database.models.Objects.metadata.create_all(sampledb.db.engine)
    return sampledb_app


@pytest.fixture
def user(flask_server):
    user = User(name="Testuser", email="example@fz-juelich.de", type=UserType.PERSON)
    with flask_server.app.app_context():
        sampledb.db.session.add(user)
        sampledb.db.session.commit()
        # force attribute refresh
        assert user.id is not None
    return user


def test_get_objects(flask_server, user):
    sampledb.object_database.models.Objects.create_object({}, {}, user_id=user.id)
    sampledb.object_database.models.Objects.create_object({}, {}, user_id=user.id)
    r = requests.get(flask_server.base_url + 'objects/')
    assert r.status_code == 200
    data = r.json()
    for obj in data:
        jsonschema.validate(obj, views.OBJECT_SCHEMA)


def test_get_object(flask_server, user):
    r = requests.get(flask_server.base_url + 'objects/0')
    assert r.status_code == 404
    obj = sampledb.object_database.models.Objects.create_object({}, {}, user_id=user.id)
    r = requests.get(flask_server.base_url + 'objects/{}'.format(obj.object_id))
    assert r.status_code == 200
    data = r.json()
    jsonschema.validate(data, views.OBJECT_SCHEMA)
    # Make sure we know about all keys in data
    assert set(data.keys()) == {'object_id', 'version_id', 'user_id', 'data', 'schema', 'last_modified'}
    # Verify their values one by one
    assert data['object_id'] == obj.object_id
    assert data['version_id'] == obj.version_id
    assert data['user_id'] == obj.user_id
    assert data['data'] == obj.data
    assert datetime.datetime.strptime(data['last_modified'], '%Y-%m-%d %H:%M:%S') == obj.utc_datetime.replace(microsecond=0)


def test_get_object_version_initial(flask_server, user):
    obj = sampledb.object_database.models.Objects.create_object({}, {}, user_id=user.id)
    r = requests.get(flask_server.base_url + 'objects/{}/versions/0'.format(obj.object_id))
    assert r.status_code == 200
    data = r.json()
    jsonschema.validate(data, views.OBJECT_SCHEMA)
    # Make sure we know about all keys in data
    assert set(data.keys()) == {'object_id', 'version_id', 'user_id', 'data', 'schema', 'last_modified'}
    # Verify their values one by one
    assert data['object_id'] == obj.object_id
    assert data['version_id'] == obj.version_id
    assert data['user_id'] == obj.user_id
    assert data['data'] == obj.data
    assert datetime.datetime.strptime(data['last_modified'], '%Y-%m-%d %H:%M:%S') == obj.utc_datetime.replace(microsecond=0)


def test_get_object_version_updated(flask_server, user):
    obj = sampledb.object_database.models.Objects.create_object({}, {}, user_id=user.id)
    obj = sampledb.object_database.models.Objects.update_object(obj.object_id, {}, {}, user_id=user.id)
    r = requests.get(flask_server.base_url + 'objects/{}/versions/{}'.format(obj.object_id, obj.version_id))
    assert r.status_code == 200
    data = r.json()
    jsonschema.validate(data, views.OBJECT_SCHEMA)
    # Make sure we know about all keys in data
    assert set(data.keys()) == {'object_id', 'version_id', 'user_id', 'data', 'schema', 'last_modified'}
    # Verify their values one by one
    assert data['object_id'] == obj.object_id
    assert data['version_id'] == obj.version_id
    assert data['user_id'] == obj.user_id
    assert data['data'] == obj.data
    assert datetime.datetime.strptime(data['last_modified'], '%Y-%m-%d %H:%M:%S') == obj.utc_datetime.replace(microsecond=0)


def test_get_object_version_old(flask_server, user):
    obj = sampledb.object_database.models.Objects.create_object({}, {}, user_id=user.id)
    sampledb.object_database.models.Objects.update_object(obj.object_id, {}, {}, user_id=user.id)
    r = requests.get(flask_server.base_url + 'objects/{}/versions/0'.format(obj.object_id, obj.version_id))
    assert r.status_code == 200
    data = r.json()
    jsonschema.validate(data, views.OBJECT_SCHEMA)
    # Make sure we know about all keys in data
    assert set(data.keys()) == {'object_id', 'version_id', 'user_id', 'data', 'schema', 'last_modified'}
    # Verify their values one by one
    assert data['object_id'] == obj.object_id
    assert data['version_id'] == obj.version_id
    assert data['user_id'] == obj.user_id
    assert data['data'] == obj.data
    assert datetime.datetime.strptime(data['last_modified'], '%Y-%m-%d %H:%M:%S') == obj.utc_datetime.replace(microsecond=0)


def test_get_object_version_missing(flask_server, user):
    obj = sampledb.object_database.models.Objects.create_object({}, {}, user_id=user.id)
    obj = sampledb.object_database.models.Objects.update_object(obj.object_id, {}, {}, user_id=user.id)
    r = requests.get(flask_server.base_url + 'objects/{}/versions/2'.format(obj.object_id, obj.version_id))
    assert r.status_code == 404


def test_create_object(flask_server, user):
    # this operation requires a logged in user
    session = requests.session()
    session.get(flask_server.base_url + 'users/{}/autologin'.format(user.id))
    assert len(sampledb.object_database.models.Objects.get_current_objects()) == 0
    data = {
        'data': {},
        'schema': {}
    }
    r = session.post(flask_server.base_url + 'objects/', json=data)
    assert r.status_code == 201
    assert len(sampledb.object_database.models.Objects.get_current_objects()) == 1
    obj = sampledb.object_database.models.Objects.get_current_objects()[0]
    assert r.headers['Location'] == flask_server.base_url + 'objects/{}'.format(obj.object_id)
    assert obj.version_id == 0
    assert obj.data == {}
    assert obj.utc_datetime <= datetime.datetime.utcnow()
    assert obj.utc_datetime >= datetime.datetime.utcnow()-datetime.timedelta(seconds=5)


def test_create_object_errors(flask_server, user):
    # this operation requires a logged in user
    session = requests.session()
    session.get(flask_server.base_url + 'users/{}/autologin'.format(user.id))
    assert len(sampledb.object_database.models.Objects.get_current_objects()) == 0
    invalid_data = [
        {
            # object ID is determined by the database
            'object_id': 1,
            'data': {},
            'schema': {}
        }, {
            # version ID has to be 0 for any new objects
            'version_id': 1,
            'data': {},
            'schema': {}
        }, {
            # user ID is always the ID of the currently logged in user
            'user_id': user.id+1,
            'data': {},
            'schema': {}
        }, {
            # TODO: should it be allowed to set last_modified time? Probably not.
            'last_modified': '2017-01-01 00:00:00',
            'data': {},
            'schema': {}
        }, {
            # attributes / keys which aren't part of the object schema are not allowed
            'invalid': '',
            'data': {},
            'schema': {}
        }, {
            # schema is required
            'data': {}
        }, {}
    ]
    for data in invalid_data:
        r = session.post(flask_server.base_url + 'objects/', json=data)
        assert r.status_code == 400
        assert len(sampledb.object_database.models.Objects.get_current_objects()) == 0
    r = session.post(flask_server.base_url + 'objects/', json=None)
    assert r.status_code == 400
    assert len(sampledb.object_database.models.Objects.get_current_objects()) == 0


def test_update_object(flask_server, user):
    # this operation requires a logged in user
    session = requests.session()
    session.get(flask_server.base_url + 'users/{}/autologin'.format(user.id))
    obj = sampledb.object_database.models.Objects.create_object(data={}, schema={}, user_id=user.id)
    data = {
        'data': {'x': 1},
        'schema': {}
    }
    r = session.put(flask_server.base_url + 'objects/{}'.format(obj.object_id), json=data)
    assert r.status_code == 200
    obj = sampledb.object_database.models.Objects.get_current_objects()[0]
    assert r.headers['Location'] == flask_server.base_url + 'objects/{}'.format(obj.object_id)
    assert obj.data == {'x': 1}
    assert obj.schema == {}
    assert obj.version_id == 1
    assert obj.utc_datetime <= datetime.datetime.utcnow()
    assert obj.utc_datetime >= datetime.datetime.utcnow()-datetime.timedelta(seconds=5)


def test_update_object_errors(flask_server, user):
    # this operation requires a logged in user
    session = requests.session()
    session.get(flask_server.base_url + 'users/{}/autologin'.format(user.id))
    assert len(sampledb.object_database.models.Objects.get_current_objects()) == 0
    r = session.put(flask_server.base_url + 'objects/0', json={'data': {}})
    assert r.status_code == 404
    assert len(sampledb.object_database.models.Objects.get_current_objects()) == 0
    obj = sampledb.object_database.models.Objects.create_object(data={}, schema={}, user_id=user.id)
    assert len(sampledb.object_database.models.Objects.get_current_objects()) == 1
    invalid_data = [
        {
            # modifying the object ID is not allowed
            'object_id': 2,
            'data': {},
            'schema': {}
        }, {
            # version ID must always me incremented by one
            'version_id': 0,
            'data': {},
            'schema': {}
        }, {
            # user ID is always the ID of the currently logged in user
            'user_id': user.id+1,
            'data': {},
            'schema': {}
        }, {
            # TODO: should it be allowed to vary last_modified time? Probably not.
            'last_modified': '2017-01-01 00:00:00',
            'data': {},
            'schema': {}
        }, {
            # attributes / keys which aren't part of the object schema are not allowed
            'invalid': '',
            'data': {},
            'schema': {}
        }, {
            # schema is required
            'data': {}
        }, {}
    ]
    for data in invalid_data:
        r = session.put(flask_server.base_url + 'objects/{}'.format(obj.object_id), json=data)
        assert r.status_code == 400
        assert len(sampledb.object_database.models.Objects.get_current_objects()) == 1
    r = session.put(flask_server.base_url + 'objects/{}'.format(obj.object_id), json=None)
    assert r.status_code == 400
    assert len(sampledb.object_database.models.Objects.get_current_objects()) == 1
