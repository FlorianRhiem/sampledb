# coding: utf-8
"""

"""

__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'

import pytest
from sampledb import db
import sampledb.logic
import sampledb.models

from ..test_utils import flask_server, app, app_context

@pytest.fixture
def user():
    user = sampledb.models.User(
        name="User",
        email="example@fz-juelich.de",
        type=sampledb.models.UserType.PERSON)
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def action():
    action = sampledb.logic.actions.create_action(
        action_type=sampledb.logic.actions.ActionType.SAMPLE_CREATION,
        name="",
        description="",
        schema={
            'title': 'Example Object',
            'type': 'object',
            'properties': {
                'name': {
                    'title': 'Object Name',
                    'type': 'text'
                },
                'keywords': {
                    'title': 'Keywords',
                    'type': 'tags'
                }
            },
            'required': ['name']
        }
    )
    return action


def test_create_object_with_tags(user, action) -> None:
    data = {
        'name': {
            '_type': 'text',
            'text': 'Example'
        },
        'keywords': {
            '_type': 'tags',
            'tags': ['Tag1', 'Tag2', 'Tag3']
        }
    }
    assert not sampledb.logic.tags.get_tags()
    sampledb.logic.objects.create_object(action_id=action.id, data=data, user_id=user.id)
    tags = sampledb.logic.tags.get_tags()
    assert len(tags) == 3
    assert all(tag.uses == 1 for tag in tags)
    assert {tag.name for tag in tags} == {'Tag1', 'Tag2', 'Tag3'}


def test_edit_object_with_tags(user, action) -> None:
    data = {
        'name': {
            '_type': 'text',
            'text': 'Example'
        },
        'keywords': {
            '_type': 'tags',
            'tags': ['Tag1', 'Tag2', 'Tag3']
        }
    }
    object = sampledb.logic.objects.create_object(action_id=action.id, data=data, user_id=user.id)
    data['keywords']['tags'] = ['Tag2', 'Tag4']
    sampledb.logic.objects.update_object(object_id=object.object_id, data=data, user_id=user.id)
    tags = sampledb.logic.tags.get_tags()
    assert len(tags) == 2
    assert all(tag.uses == 1 for tag in tags)
    assert {tag.name for tag in tags} == {'Tag2', 'Tag4'}


def test_create_multiple_objects_with_tags(user, action) -> None:
    data = {
        'name': {
            '_type': 'text',
            'text': 'Example'
        },
        'keywords': {
            '_type': 'tags',
            'tags': ['Tag1', 'Tag2', 'Tag3']
        }
    }
    sampledb.logic.objects.create_object(action_id=action.id, data=data, user_id=user.id)
    data['keywords']['tags'] = ['Tag2', 'Tag4']
    sampledb.logic.objects.create_object(action_id=action.id, data=data, user_id=user.id)
    tags = sampledb.logic.tags.get_tags()
    assert {tag.name: tag.uses for tag in tags} == {'Tag1': 1, 'Tag2': 2, 'Tag3': 1, 'Tag4': 1}
