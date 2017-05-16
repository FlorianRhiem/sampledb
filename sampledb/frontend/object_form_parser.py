# coding: utf-8
"""

"""

import functools
import pint
from ..logic import schemas, errors
from ..logic.units import ureg


def form_data_parser(func):
    @functools.wraps(func)
    def wrapper(form_data, schema, id_prefix, errors, required=False):
        try:
            return func(form_data, schema, id_prefix, errors, required=required)
        except ValueError as e:
            for name in form_data:
                if name.startswith(id_prefix) and '_' not in name[len(id_prefix)+1:]:
                    errors[name] = str(e)
            return None
        except errors.ValidationError as e:
            for name in form_data:
                if name.startswith(id_prefix) and '_' not in name[len(id_prefix)+1:]:
                    errors[name] = e.message
            return None
    return wrapper


@form_data_parser
def parse_any_form_data(form_data, schema, id_prefix, errors, required=False):
    if schema.get('type') == 'object':
        return parse_object_form_data(form_data, schema, id_prefix, errors, required=required)
    elif schema.get('type') == 'array':
        return parse_array_form_data(form_data, schema, id_prefix, errors, required=required)
    elif schema.get('type') == 'text':
        return parse_text_form_data(form_data, schema, id_prefix, errors, required=required)
    elif schema.get('type') == 'sample':
        return parse_sample_form_data(form_data, schema, id_prefix, errors, required=required)
    elif schema.get('type') == 'datetime':
        return parse_datetime_form_data(form_data, schema, id_prefix, errors, required=required)
    elif schema.get('type') == 'bool':
        return parse_boolean_form_data(form_data, schema, id_prefix, errors, required=required)
    elif schema.get('type') == 'quantity':
        return parse_quantity_form_data(form_data, schema, id_prefix, errors, required=required)
    raise ValueError('invalid schema')


@form_data_parser
def parse_text_form_data(form_data, schema, id_prefix, errors, required=False):
    keys = [key for key in form_data.keys() if key.startswith(id_prefix)]
    if keys != [id_prefix + '_text']:
        raise ValueError('invalid text form data')
    text = form_data.get(id_prefix + '_text', [''])[0]
    data = {
        '_type': 'text',
        'text': str(text)
    }
    schemas.validate(data, schema)
    return data


@form_data_parser
def parse_sample_form_data(form_data, schema, id_prefix, errors, required=False):
    keys = [key for key in form_data.keys() if key.startswith(id_prefix)]
    if keys != [id_prefix + '_oid']:
        raise ValueError('invalid sample form data')
    object_id = form_data.get(id_prefix + '_oid', [''])[0]
    if not object_id:
        if not required:
            return None
        else:
            raise ValueError('Please select a sample.')
    try:
        object_id = int(object_id)
    except ValueError:
        raise ValueError('object_id must be int')
    data = {
        '_type': 'sample',
        'object_id': object_id
    }
    schemas.validate(data, schema)
    return data


@form_data_parser
def parse_quantity_form_data(form_data, schema, id_prefix, errors, required=False):
    keys = [key for key in form_data.keys() if key.startswith(id_prefix)]
    # TODO: validate schema?
    if set(keys) != {id_prefix + '_magnitude', id_prefix + '_units'} and keys != [id_prefix + '_magnitude']:
        raise ValueError('invalid quantity form data')
    magnitude = form_data[id_prefix + '_magnitude'][0].strip()
    if not magnitude:
        if not required:
            return None
        else:
            raise ValueError('Please enter a magnitude.')
    try:
        magnitude = float(magnitude)
    except ValueError:
        raise ValueError('The magnitude must be a number.')
    if id_prefix + '_units' in form_data:
        units = form_data[id_prefix + '_units'][0]
        try:
            pint_units = ureg.Unit(units)
        except pint.UndefinedUnitError:
            raise ValueError('invalid units')
    else:
        units = '1'
        pint_units = ureg.Unit('1')
    dimensionality = str(pint_units.dimensionality)
    magnitude_in_base_units = ureg.Quantity(magnitude, pint_units).to_base_units().magnitude
    data = {
        '_type': 'quantity',
        'magnitude_in_base_units': magnitude_in_base_units,
        'dimensionality': dimensionality,
        'units': units
    }
    schemas.validate(data, schema)
    return data


@form_data_parser
def parse_datetime_form_data(form_data, schema, id_prefix, errors, required=False):
    keys = [key for key in form_data.keys() if key.startswith(id_prefix)]
    # TODO: validate schema?
    if keys != [id_prefix + '_datetime']:
        raise ValueError('invalid datetime form data')
    utc_datetime = form_data.get(id_prefix + '_datetime', [''])[0]
    data = {
        '_type': 'datetime',
        'utc_datetime': utc_datetime
    }
    schemas.validate(data, schema)
    return data


@form_data_parser
def parse_boolean_form_data(form_data, schema, id_prefix, errors, required=False):
    keys = [key for key in form_data.keys() if key.startswith(id_prefix)]
    # TODO: validate schema?
    if set(keys) == {id_prefix + '_hidden', id_prefix + '_value'}:
        value = True
    elif keys == [id_prefix + '_hidden']:
        value = False
    else:
        raise ValueError('invalid boolean form data')
    return {
        '_type': 'bool',
        'value': value
    }


@form_data_parser
def parse_array_form_data(form_data, schema, id_prefix, errors, required=False):
    keys = [key for key in form_data.keys() if key.startswith(id_prefix)]
    item_schema = schema['items']
    item_indices = set()
    for key in keys:
        key_rest = key.replace(id_prefix, '', 1)
        if not key_rest.startswith('_'):
            raise ValueError('invalid array form data')
        key_parts = key_rest.split('_')
        if not key_parts[0] == '':
            raise ValueError('invalid array form data')
        try:
            item_index = int(key_parts[1])
        except ValueError:
            raise ValueError('invalid array form data')
        item_indices.add(item_index)
    items = []
    if item_indices:
        num_items = max([i for i in item_indices])+1
        for i in range(num_items):
            if i not in item_indices:
                items.append(None)
            else:
                item_id_prefix = id_prefix+'_{}'.format(i)
                items.append(parse_any_form_data(form_data, item_schema, item_id_prefix, errors))
    schemas.validate(items, schema)
    return items


@form_data_parser
def parse_object_form_data(form_data, schema, id_prefix, errors, required=False):
    assert schema['type'] == 'object'
    data = {}
    for property_name, property_schema in schema['properties'].items():
        property_id_prefix = id_prefix + '_' + property_name
        if any(key.startswith(id_prefix) for key in form_data.keys()):
            property_required = (property_name in schema.get('required', []))
            property = parse_any_form_data(form_data, property_schema, property_id_prefix, errors, required=property_required)
            if property is not None:
                data[property_name] = property
    schemas.validate(data, schema)
    return data


def parse_form_data(form_data, schema):
    id_prefix = 'object'
    errors = {}
    data = parse_object_form_data(form_data, schema, id_prefix, errors)
    return data, errors

