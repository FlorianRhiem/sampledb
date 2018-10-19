# coding: utf-8
"""

"""


import requests
import pytest

import sampledb
import sampledb.models
import sampledb.logic

from tests.test_utils import flask_server, app, app_context


@pytest.fixture
def user_session(flask_server):
    user = sampledb.models.User(name="Basic User", email="example@fz-juelich.de", type=sampledb.models.UserType.PERSON)
    sampledb.db.session.add(user)
    sampledb.db.session.commit()
    session = requests.session()
    assert session.get(flask_server.base_url + 'users/{}/autologin'.format(user.id)).status_code == 200
    session.user_id = user.id
    return session


@pytest.fixture
def action(flask_server):
    action = sampledb.models.Action(
        action_type=sampledb.models.ActionType.SAMPLE_CREATION,
        name='ExampleAction',
        schema={
            'title': 'Example Object',
            'type': 'object',
            'properties': {}
        },
        description='',
        instrument_id=None
    )
    sampledb.db.session.add(action)
    sampledb.db.session.commit()
    # force attribute refresh
    assert action.id is not None
    return action


def test_generate_pdfexport(action, flask_server, user_session):
    object = sampledb.logic.objects.create_object(action.id, {}, user_session.user_id)
    r = user_session.get(flask_server.base_url + 'objects/{}/pdf'.format(object.object_id))
    assert r.status_code == 200
    assert len(r.content) > 0
    assert r.headers["Content-Type"] == 'application/pdf'
