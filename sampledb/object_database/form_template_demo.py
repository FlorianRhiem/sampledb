# coding: utf-8
"""

"""

import flask
import json
import jsonschema
import os

from .views import object_api, SCHEMA_DIR
from .datatypes import JSONEncoder

__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'


schema = json.load(open(os.path.join(SCHEMA_DIR, 'ombe.custom.json'), 'r'))
data = json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'example_data', 'ombe.json'), 'r'))

jsonschema.Draft4Validator.check_schema(schema)
jsonschema.validate(data, schema)


def to_datatype(obj):
    return json.loads(json.dumps(obj), object_hook=JSONEncoder.object_hook)


@object_api.route('/test')
def render_schema():
    flask.current_app.jinja_env.filters['to_datatype'] = to_datatype
    return flask.render_template('form_base.html', schema=schema, data=data)
