# coding: utf-8
"""

"""

import jsonschema
from .. import db
from ..models import User, Instrument, Action

__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'


def create_instrument(name, description):
    instrument = Instrument(
        name=name,
        description=description
    )
    db.session.add(instrument)
    db.session.commit()
    return instrument


def get_instruments():
    return Instrument.query.all()


def get_instrument(instrument_id):
    return Instrument.query.get(instrument_id)


def update_instrument(instrument_id, name, description, ):
    instrument = Instrument.query.get(instrument_id)
    instrument.name = name
    instrument.description = description
    db.session.add(instrument)
    db.session.commit()
    return instrument


def add_instrument_responsible_user(instrument_id, user_id):
    instrument = Instrument.query.get(instrument_id)
    user = User.query.get(user_id)
    instrument.responsible_users.append(user)
    db.session.add(instrument)
    db.session.commit()


def remove_instrument_responsible_user(instrument_id, user_id):
    instrument = Instrument.query.get(instrument_id)
    user = User.query.get(user_id)
    instrument.responsible_users.remove(user)
    db.session.add(instrument)
    db.session.commit()


def create_action(name, description, schema, instrument_id=None):
    jsonschema.Draft4Validator.check_schema(schema)
    action = Action(
        name=name,
        description=description,
        schema=schema,
        instrument_id=instrument_id
    )
    db.session.add(action)
    db.session.commit()
    return action


def get_actions():
    return Action.query.all()


def get_action(action_id):
    return Action.query.get(action_id)


def update_action(action_id, name, description, schema):
    jsonschema.Draft4Validator.check_schema(schema)
    action = Action.query.get(action_id)
    action.name = name
    action.description = description
    action.schema = schema
    db.session.add(action)
    db.session.commit()
    return action
