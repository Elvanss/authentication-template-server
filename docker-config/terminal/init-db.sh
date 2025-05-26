#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE ms_user;
    CREATE DATABASE ms_auth;
    CREATE DATABASE ms_notification;
EOSQL
