# coding: utf-8
"""

"""

import pytest
import sampledb
from sampledb.models import User, UserType
from sampledb.logic import instruments, errors


__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'


@pytest.fixture(autouse=True)
def app_context():
    app = sampledb.create_app()
    with app.app_context():
        # fully empty the database first
        sampledb.db.MetaData(reflect=True, bind=sampledb.db.engine).drop_all()
        # recreate the tables used by this application
        sampledb.db.metadata.create_all(bind=sampledb.db.engine)
        yield app


def test_create_instrument():
    assert len(instruments.get_instruments()) == 0
    instrument = instruments.create_instrument(name="Example Instrument", description="")
    assert len(instruments.get_instruments()) == 1
    assert instrument == instruments.get_instrument(instrument_id=instrument.id)
    assert len(instrument.responsible_users) == 0


def test_update_instrument():
    instrument = instruments.create_instrument(name="Example Instrument", description="")
    instruments.update_instrument(instrument_id=instrument.id, name="Test", description="desc")
    instrument = instruments.get_instrument(instrument_id=instrument.id)
    assert instrument.name == "Test"
    assert instrument.description == "desc"
    assert len(instrument.responsible_users) == 0


def test_instrument_responsible_users():
    user = User(name="Testuser", email="example@fz-juelich.de", type=UserType.PERSON)
    sampledb.db.session.add(user)
    sampledb.db.session.commit()
    instrument = instruments.create_instrument(name="Example Instrument", description="")
    assert len(instrument.responsible_users) == 0
    instruments.add_instrument_responsible_user(instrument_id=instrument.id, user_id=user.id)
    assert len(instrument.responsible_users) == 1
    with pytest.raises(errors.UserAlreadyResponsibleForInstrumentError):
        instruments.add_instrument_responsible_user(instrument_id=instrument.id, user_id=user.id)
    instruments.remove_instrument_responsible_user(instrument_id=instrument.id, user_id=user.id)
    assert len(instrument.responsible_users) == 0
    with pytest.raises(errors.UserNotResponsibleForInstrumentError):
        instruments.remove_instrument_responsible_user(instrument_id=instrument.id, user_id=user.id)
    with pytest.raises(errors.InstrumentDoesNotExistError):
        instruments.add_instrument_responsible_user(instrument_id=instrument.id+1, user_id=user.id)
    with pytest.raises(errors.UserDoesNotExistError):
        instruments.add_instrument_responsible_user(instrument_id=instrument.id, user_id=user.id+1)
    with pytest.raises(errors.InstrumentDoesNotExistError):
        instruments.remove_instrument_responsible_user(instrument_id=instrument.id+1, user_id=user.id)
    with pytest.raises(errors.UserDoesNotExistError):
        instruments.remove_instrument_responsible_user(instrument_id=instrument.id, user_id=user.id+1)


def test_get_missing_instrument():
    instrument = instruments.create_instrument(name="Example Instrument", description="")
    with pytest.raises(errors.InstrumentDoesNotExistError):
        instruments.get_instrument(instrument_id=instrument.id+1)


def test_update_missing_instrument():
    instrument = instruments.create_instrument(name="Example Instrument", description="")
    with pytest.raises(errors.InstrumentDoesNotExistError):
        instruments.update_instrument(instrument_id=instrument.id+1, name="Test", description="desc")
