from paths import *
from peewee import *
import os

custom_db = SqliteDatabase(os.path.join(MANAGER_PATH, 'ca_manager.db'))

class CustomModel(Model):
    class Meta:
        database = custom_db
