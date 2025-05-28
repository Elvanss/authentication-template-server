#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ms_user') THEN
            CREATE DATABASE ms_user;
        END IF;
        IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ms_auth') THEN
            CREATE DATABASE ms_auth;
        END IF;
        IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ms_notification') THEN
            CREATE DATABASE ms_notification;
        END IF;
    END
    \$\$;
EOSQL