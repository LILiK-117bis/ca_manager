"""
Provide a "Generic ForeignKey", similar to Django.  A "GFK" is composed of two
columns: an object ID and an object type identifier.  The object types are
collected in a global registry (all_models), so all you need to do is subclass
``gfk.Model`` and your model will be added to the registry.

Example:

class Tag(Model):
    tag = CharField()
    object_type = CharField(null=True)
    object_id = IntegerField(null=True)
    object = GFKField('object_type', 'object_id')

class Blog(Model):
    tags = ReverseGFK(Tag, 'object_type', 'object_id')

class Photo(Model):
    tags = ReverseGFK(Tag, 'object_type', 'object_id')

tag.object -> a blog or photo
blog.tags -> select query of tags for ``blog`` instance
Blog.tags -> select query of all tags for Blog instances
"""

from peewee import *
from peewee import ModelBase as _BaseModel
from peewee import Model as _Model
from peewee import SelectQuery
from peewee import Update as UpdateQuery
from peewee import with_metaclass


all_models = set()
table_cache = {}


class BaseModel(_BaseModel):
    def __new__(cls, name, bases, attrs):
        cls = super(BaseModel, cls).__new__(cls, name, bases, attrs)
        if name not in ('_metaclass_helper_', 'Model'):
            all_models.add(cls)
        return cls

class Model(with_metaclass(BaseModel, _Model)):
    def __init__(self, *args, **kwargs):
        self._obj_cache = {}
        return super(Model, self).__init__(*args, **kwargs)


def get_model(tbl_name):
    if tbl_name not in table_cache:
        for model in all_models:
            if model._meta.table_name == tbl_name:
                table_cache[tbl_name] = model
                break
    return table_cache.get(tbl_name)

class BoundGFKField(object):
    __slots__ = ('model', 'gfk_field')

    def __init__(self, model, gfk_field):
        self.model = model
        self.gfk_field = gfk_field

    @property
    def unique(self):
        indexes = self.model._meta.indexes
        fields = set((self.gfk_field.model_type_field,
                      self.gfk_field.model_id_field))
        for (indexed_columns, is_unique) in indexes:
            if not fields - set(indexed_columns):
                return True
        return False

    @property
    def primary_key(self):
        pk = self.model._meta.primary_key
        if isinstance(pk, CompositeKey):
            fields = set((self.gfk_field.model_type_field,
                          self.gfk_field.model_id_field))
            if not fields - set(pk.field_names):
                return True
        return False

    def __eq__(self, other):
        meta = self.model._meta
        type_field = meta.fields[self.gfk_field.model_type_field]
        id_field = meta.fields[self.gfk_field.model_id_field]
        return (
            (type_field == other._meta.table_name) &
            (id_field == other.get_id()))

    def __ne__(self, other):
        other_cls = type(other)
        type_field = other._meta.fields[self.gfk_field.model_type_field]
        id_field = other._meta.fields[self.gfk_field.model_id_field]
        return (
            (type_field == other._meta.table_name) &
            (id_field != other.get_id()))


class GFKField(object):
    def __init__(self, model_type_field='object_type',
                 model_id_field='object_id'):
        self.model_type_field = model_type_field
        self.model_id_field = model_id_field
        self.att_name = '.'.join((self.model_type_field, self.model_id_field))

    def get_obj(self, instance):
        data = instance.__data__
        if data.get(self.model_type_field) and data.get(self.model_id_field):
            tbl_name = data[self.model_type_field]
            model = get_model(tbl_name)
            if not model:
                raise AttributeError('Model for table "%s" not found in GFK '
                                     'lookup.' % tbl_name)
            query = model.select().where(
                model._meta.primary_key == data[self.model_id_field])
            return query.get()

    def __get__(self, instance, instance_type=None):
        if instance:
            if self.att_name not in instance._obj_cache:
                rel_obj = self.get_obj(instance)
                if rel_obj:
                    instance._obj_cache[self.att_name] = rel_obj
            return instance._obj_cache.get(self.att_name)
        return BoundGFKField(instance_type, self)

    def __set__(self, instance, value):
        instance._obj_cache[self.att_name] = value
        instance.__data__[self.model_type_field] = value._meta.table_name
        instance.__data__[self.model_id_field] = value.get_id()


class ReverseGFK(object):
    def __init__(self, model, model_type_field='object_type',
                 model_id_field='object_id'):
        self.model = model
        self.model_type_field = model._meta.fields[model_type_field]
        self.model_id_field = model._meta.fields[model_id_field]

    def __get__(self, instance, instance_type=None):
        if instance:
            return self.model.select().where(
                (self.model_type_field == instance._meta.table_name) &
                (self.model_id_field == instance.get_id())
            )
        else:
            return self.model.select().where(
                self.model_type_field == instance_type._meta.table_name
            )

    def __set__(self, instance, value):
        mtv = instance._meta.table_name
        miv = instance.get_id()
        if (isinstance(value, SelectQuery) and
                value.model == self.model):
            UpdateQuery(self.model, {
                self.model_type_field: mtv,
                self.model_id_field: miv,
            }).where(value._where).execute()
        elif all(map(lambda i: isinstance(i, self.model), value)):
            for obj in value:
                setattr(obj, self.model_type_field.name, mtv)
                setattr(obj, self.model_id_field.name, miv)
                obj.save()
        else:
            raise ValueError('ReverseGFK field unable to handle "%s"' % value)
