#!/bin/sh
chown sampledb:sampledb "${SAMPLEDB_FILE_STORAGE_PATH}"
su sampledb -c "/home/sampledb/env/bin/python -m sampledb run"

