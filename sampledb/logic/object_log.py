# coding: utf-8
"""

"""

import datetime
import typing
from . import objects
from . import permissions
from ..models import ObjectLogEntry, ObjectLogEntryType
from .. import db

__author__ = 'Florian Rhiem <f.rhiem@fz-juelich.de>'


def get_object_log_entries(object_id: int, user_id: int=None) -> typing.List[ObjectLogEntry]:
    object_log_entries = ObjectLogEntry.query.filter_by(object_id=object_id).order_by(db.desc(ObjectLogEntry.utc_datetime)).all()
    processed_object_log_entries = []
    for object_log_entry in object_log_entries:
        if object_log_entry.type == ObjectLogEntryType.USE_OBJECT_IN_MEASUREMENT:
            measurement = objects.get_object(object_id=object_log_entry.data['measurement_id'])
            object_log_entry.data['measurement'] = measurement
            if user_id is not None and permissions.Permissions.READ not in permissions.get_user_object_permissions(object_id=measurement.object_id, user_id=user_id):
                continue
        elif object_log_entry.type == ObjectLogEntryType.USE_OBJECT_IN_SAMPLE_CREATION:
            sample = objects.get_object(object_id=object_log_entry.data['sample_id'])
            object_log_entry.data['sample'] = sample
            if user_id is not None and permissions.Permissions.READ not in permissions.get_user_object_permissions(object_id=sample.object_id, user_id=user_id):
                continue
        processed_object_log_entries.append(object_log_entry)
    return processed_object_log_entries


def _store_new_log_entry(type: ObjectLogEntryType, object_id: int, user_id: int, data: dict):
    object_log_entry = ObjectLogEntry(
        type=type,
        object_id=object_id,
        user_id=user_id,
        data=data,
        utc_datetime=datetime.datetime.utcnow()
    )
    db.session.add(object_log_entry)
    db.session.commit()


def create_object(user_id: int, object_id: int):
    _store_new_log_entry(
        type=ObjectLogEntryType.CREATE_OBJECT,
        object_id=object_id,
        user_id=user_id,
        data={
        }
    )


def edit_object(user_id: int, object_id: int, version_id: int):
    _store_new_log_entry(
        type=ObjectLogEntryType.EDIT_OBJECT,
        object_id=object_id,
        user_id=user_id,
        data={
            'version_id': version_id
        }
    )


def restore_object_version(user_id: int, object_id: int, version_id: int, restored_version_id: int):
    _store_new_log_entry(
        type=ObjectLogEntryType.RESTORE_OBJECT_VERSION,
        object_id=object_id,
        user_id=user_id,
        data={
            'version_id': version_id,
            'restored_version_id': restored_version_id
        }
    )


def use_object_in_measurement(user_id: int, object_id: int, measurement_id: int):
    _store_new_log_entry(
        type=ObjectLogEntryType.USE_OBJECT_IN_MEASUREMENT,
        object_id=object_id,
        user_id=user_id,
        data={
            'measurement_id': measurement_id
        }
    )


def use_object_in_sample(user_id: int, object_id: int, sample_id: int):
    _store_new_log_entry(
        type=ObjectLogEntryType.USE_OBJECT_IN_SAMPLE_CREATION,
        object_id=object_id,
        user_id=user_id,
        data={
            'sample_id': sample_id
        }
    )


def post_comment(user_id: int, object_id: int, comment_id: int):
    _store_new_log_entry(
        type=ObjectLogEntryType.POST_COMMENT,
        object_id=object_id,
        user_id=user_id,
        data={
            'comment_id': comment_id
        }
    )


def upload_file(user_id: int, object_id: int, file_id: int):
    _store_new_log_entry(
        type=ObjectLogEntryType.UPLOAD_FILE,
        object_id=object_id,
        user_id=user_id,
        data={
            'file_id': file_id
        }
    )
