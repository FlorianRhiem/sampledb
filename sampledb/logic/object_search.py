# coding: utf-8
"""

"""

import json
import typing
from sqlalchemy import String, and_, or_
from sqlalchemy.sql.schema import Column
from sqlalchemy.sql.elements import BinaryExpression
from typing import Any
from . import where_filters
from . import datatypes
from . import node

def trans(data, tree, get_quantity, get_wherefilter):
    """converts tree by Post-Order pass in the type of data,
    which is set through get_wherefilter"""
    if tree.left is None:
        return get_quantity(data, tree.operator)
    else:
        return get_wherefilter(trans(data, tree.left, get_quantity, get_wherefilter),
                    trans(data, tree.right, get_quantity, get_wherefilter), tree.operator)


def get_quantity(data: Column, cond: str) -> typing.Union[datatypes.Quantity, BinaryExpression]:
    """gets treeelement, creates quantity"""

    # Try parsing cond as quantity
    had_decimal_point = False
    for index, character in enumerate(cond):
        if not character.isdigit():
            if not had_decimal_point and character == ".":
                had_decimal_point = True
            else:
                len_magnitude = index
                break
    else:
        len_magnitude = len(cond)
    if len_magnitude > 0:
        magnitude = float(cond[:len_magnitude])
        units = cond[len_magnitude:]
        if not units:
            units = None
        quantity = datatypes.Quantity(magnitude, units)
        return quantity

    attributes = cond.split('.')
    return data[attributes]


def get_wherefilter(rg1, rg2, operator) -> Any:
    """returns a filter_func"""
    if (operator == "&&"):
        return and_(rg1, rg2)
    if (operator == "||"):
        return or_(rg1, rg2)
    if (operator == "=="):
        return where_filters.quantity_equals(rg1, rg2)
    if (operator == ">"):
        return where_filters.quantity_greater_than(rg1, rg2)
    if (operator == "<"):
        return where_filters.quantity_less_than(rg1, rg2)
    if (operator == ">="):
        return where_filters.quantity_greater_than_equals(rg1, rg2)
    if (operator == "<="):
        return where_filters.quantity_less_than_equals(rg1, rg2)


def generate_filter_func(query_string: str, use_advanced_search: bool) -> typing.Callable:
    """
    Generates a filter function for use with SQLAlchemy and the JSONB data
    attribute in the object tables.

    The generated filter functions can be used for objects.get_objects()

    :param query_string: the query string
    :param use_advanced_search: whether to use simple text search (False) or advanced search (True)
    :return: filter func
    """
    if query_string:
        if use_advanced_search:
            # Advanced search using parser and where_filters
            def filter_func(data, query_string=query_string):

                """ Filter objects based on search query string """
                query_string = node.replace(query_string)
                binary_tree = node.parsing_in_tree(query_string)
                return trans(data, binary_tree, get_quantity, get_wherefilter)
        else:
            # Simple search in values
            def filter_func(data, query_string=query_string):
                """ Filter objects based on search query string """
                # The query string is converted to json to escape quotes, backslashes, etc
                query_string = json.dumps(query_string)[1:-1]
                return data.cast(String).like('%: "%'+query_string+'%"%')

    else:
        def filter_func(data):
            """ Return all objects"""
            return True
    return filter_func
