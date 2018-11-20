# coding: utf-8
"""

"""

import requests
import pytest
import json

import sampledb
import sampledb.logic
import sampledb.models


from tests.test_utils import flask_server, app, app_context


@pytest.fixture
def auth_user(flask_server):
    with flask_server.app.app_context():
        user = sampledb.models.User(name="Basic User", email="example@fz-juelich.de", type=sampledb.models.UserType.PERSON)
        sampledb.logic.authentication.insert_user_and_authentication_method_to_db(
            user,
            login='username',
            password='password',
            user_type=sampledb.logic.authentication.AuthenticationType.OTHER
        )
        assert user.id is not None
    return ('username', 'password'), user


@pytest.fixture
def auth(auth_user):
    return auth_user[0]


@pytest.fixture
def user(auth_user):
    return auth_user[1]


def test_get_instrument(flask_server, auth, user):
    r = requests.get(flask_server.base_url + 'api/v1/instruments/1', auth=auth)
    assert r.status_code == 404

    instrument = sampledb.logic.instruments.create_instrument(
        name="Example Instrument",
        description="This is an example instrument"
    )
    r = requests.get(flask_server.base_url + 'api/v1/instruments/{}'.format(instrument.id), auth=auth)
    assert r.status_code == 200
    assert r.json() == {
        'instrument_id': instrument.id,
        'name': "Example Instrument",
        'description': "This is an example instrument",
        'instrument_scientists': []
    }

    sampledb.logic.instruments.add_instrument_responsible_user(instrument.id, user.id)
    r = requests.get(flask_server.base_url + 'api/v1/instruments/{}'.format(instrument.id), auth=auth)
    assert r.status_code == 200
    assert r.json() == {
        'instrument_id': instrument.id,
        'name': "Example Instrument",
        'description': "This is an example instrument",
        'instrument_scientists': [user.id]
    }


def test_get_instruments(flask_server, auth):
    r = requests.get(flask_server.base_url + 'api/v1/instruments/', auth=auth)
    assert r.status_code == 200
    assert r.json() == []

    instrument = sampledb.logic.instruments.create_instrument(
        name="Example Instrument",
        description="This is an example instrument",
    )
    r = requests.get(flask_server.base_url + 'api/v1/instruments/', auth=auth)
    assert r.status_code == 200
    assert r.json() == [
        {
            'instrument_id': instrument.id,
            'name': "Example Instrument",
            'description': "This is an example instrument",
            'instrument_scientists': []
        }
    ]