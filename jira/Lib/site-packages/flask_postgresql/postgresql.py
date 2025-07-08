import logging

import psycopg2
from flask import current_app, g

logger = logging.getLogger(__name__)


class PostgreSQL(object):
    def __init__(self, app=None):
        if app is not None:
            self.app = app
            self.init_app(app)
        else:
            self.app = None

    def init_app(self, app):
        app.config.setdefault('PG_HOST', 'localhost')
        app.config.setdefault('PG_USERNAME', None)
        app.config.setdefault('PG_PASSWORD', None)
        app.config.setdefault('PG_PORT', 5432)
        app.config.setdefault('PG_DB', None)
        app.config.setdefault('PG_APPLICATION_NAME', 'Flask-PostgreSQL')

        app.teardown_appcontext(self.teardown)

    def connect(self):
        connection = None
        try:
            connection = psycopg2.connect(
                host=current_app.config['PG_HOST'],
                user=current_app.config['PG_USERNAME'],
                password=current_app.config['PG_PASSWORD'],
                port=current_app.config['PG_PORT'],
                dbname=current_app.config['PG_DB'],
                application_name=current_app.config['PG_APPLICATION_NAME']
            )

            return connection
        except psycopg2.DatabaseError as e:
            logger.error(e)
        finally:
            if connection:
                logger.debug('Connection opened successfully')

    def teardown(self, exception):
        db = getattr(g, '_postgres_db', None)
        if db is not None:
            db.close()
            logger.debug('Connection closed')

    @property
    def connection(self):
        db = getattr(g, '_postgres_db', None)
        if db is None:
            db = g._postgres_db = self.connect()
        return db
