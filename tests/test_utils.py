# coding: utf-8
"""

"""
import logging
import os
import pytest
import random
import threading
import time
import requests
import sqlalchemy
import flask
import flask_login

import sampledb


def test_success():
    """
    This test will always pass. It is meant to help detect the pytest tests in the sub-packages.
    """
    assert True


@pytest.fixture
def flask_server(app):
    if not getattr(app, 'has_shutdown_route', False):
        @app.route('/shutdown', methods=['POST'])
        def shutdown():
            func = flask.request.environ.get('werkzeug.server.shutdown')
            if func is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            func()
            return 'Server shutting down...'
        app.has_shutdown_route = True

    port = random.randint(10000, 20000)
    server_thread = threading.Thread(target=lambda: app.run(port=port, debug=True, use_reloader=False), daemon=True)
    server_thread.start()
    server_thread.app = app
    server_thread.base_url = 'http://localhost:{0}/'.format(port)
    server_thread.api_url = server_thread.base_url + 'api/'
    # short delay to allow the web server to start
    time.sleep(0.1)
    yield server_thread
    r = requests.post(server_thread.base_url + 'shutdown')
    assert r.status_code == 200
    server_thread.join()


@pytest.fixture
def app():
    logging.getLogger('flask.app').setLevel(logging.WARNING)
    os.environ['FLASK_ENV'] = 'development'
    os.environ['FLASK_TESTING'] = 'True'
    sampledb_app = sampledb.create_app()

    @sampledb_app.route('/users/me/loginstatus')
    def check_login():
        return flask.jsonify(flask_login.current_user.is_authenticated)

    @sampledb_app.route('/users/<int:user_id>/autologin')
    def autologin(user_id):
        user = sampledb.models.User.query.get(user_id)
        assert user is not None
        flask_login.login_user(user)
        return ''

    with sampledb_app.app_context():
        # fully empty the database first
        metadata = sqlalchemy.MetaData(bind=sampledb.db.engine)
        metadata.reflect()
        metadata.drop_all()
        # recreate the tables used by this application
        sampledb.db.metadata.create_all(bind=sampledb.db.engine)

    return sampledb_app


@pytest.fixture(autouse=True)
def app_context():
    app = sampledb.create_app()
    with app.app_context():
        # fully empty the database first
        metadata = sampledb.db.MetaData(bind=sampledb.db.engine)
        metadata.reflect()
        metadata.drop_all()
        # recreate the tables used by this application
        sampledb.db.metadata.create_all(bind=sampledb.db.engine)
        yield app
