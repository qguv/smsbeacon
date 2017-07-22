from flask_wtf import FlaskForm
from wtforms import BooleanField, StringField, TextAreaField, IntegerField, HiddenField
from wtforms.validators import DataRequired, InputRequired, Optional, Length, ValidationError, NumberRange
from werkzeug.datastructures import MultiDict

# fix dumb checkbox bug: https://stackoverflow.com/a/38102472
BooleanField.false_values = {False, 'false', ''}

import settings
from utils import random_token, call_some, normal_telno

import string

class InClassLength():
    '''counts the number of characters within a character class'''
    def __init__(self, chars, name, min=0, max=None):
        self.chars = chars
        self.name = name
        self.min = min
        self.max = max

    def __call__(self, form, field):
        n = 0
        for c in field.data:
            if c in self.chars:
                n += 1

        if n < self.min:
            raise ValidationError("not enough {} ({} needed)".format(self.name, self.min))
        if self.max is not None and n > self.max:
            raise ValidationError("too many {} ({} maximum)".format(self.name, self.max))

class InputRequiredIf():
    '''a wtforms validator which makes a field required if a given different
    field is set and has a truthy value'''

    def __init__(self, other_field_name, *args, **kwargs):
        self.other_field_name = other_field_name
        self.args = args
        self.kwargs = kwargs

    def __call__(self, form, field):
        other_field = form._fields.get(self.other_field_name)
        if other_field is None:
            raise ValidationError('no field named "{}" in form'.format(self.other_field_name))
        if other_field.data:
            InputRequired(*self.args, **self.kwargs)(form, field)
        else:
            Optional(*self.args, **self.kwargs)(form, field)

class Beacon(FlaskForm):

    telno = StringField("Beacon SMS number:", [DataRequired(), InClassLength(string.digits, 'digits', min=10)])
    nickname = StringField("Nickname:", [DataRequired()], default="beacon")
    description = TextAreaField("Description?")
    locid = StringField("Short location name (like ATL or WBG):", [DataRequired(), Length(min=3, max=7)])

    plivo_id = StringField("Plivo ID:", [DataRequired()])
    plivo_token = StringField("Plivo token:", [DataRequired()])

    autosend = BooleanField("Automatically send reports?", default=True)
    autosend_delay_minutes = IntegerField("...after how many minutes?", [InputRequiredIf('autosend'), NumberRange(min=0)], default=5)

    prune = BooleanField("Automatically prune sent or rejected reports?", default=True)
    prune_delay_hours = IntegerField("...after how many hours?", [InputRequiredIf('prune'), NumberRange(min=0)], default=48)

    token_lifetime_minutes = IntegerField("Automatically log out after how many minutes?", [DataRequired(), NumberRange(min=1)], default=5)
    new_secret = BooleanField("Recalculate plivo secret?", default=False)

    secret = HiddenField()

    @classmethod
    def from_db(cls, d):
        '''create a form from a database object'''

        d['autosend'] = d['autosend_delay'] is not None
        if d['autosend']:
            d['autosend_delay_minutes'] = d['autosend_delay'] // 60

        d['prune'] = d['prune_delay'] is not None
        if d['prune']:
            d['prune_delay_hours'] = d['prune_delay'] // 360

        d['token_lifetime_minutes'] = d['token_lifetime'] // 60

        d['locid'] = d['locid']

        return cls(MultiDict(d))

    def into_db(self):
        '''turn the form response into a database object. must handle fields
        being None, as they are just after the form object is instantiated.'''
        return dict(
            telno = call_some(self.telno.data, normal_telno),
            nickname = self.nickname.data,
            description = self.description.data,
            locid = call_some(self.locid.data, lambda x: x.lower()),
            plivo_id = self.plivo_id.data,
            plivo_token = self.plivo_token.data,
            autosend_delay = int(self.autosend_delay_minutes.data) * 60 if self.autosend.data else None,
            prune_delay = int(self.prune_delay_hours.data) * 360 if self.prune.data else None,
            token_lifetime = int(self.token_lifetime_minutes.data) * 60,
            secret = random_token(settings.plivo_url_secret_length) if self.new_secret.data or not self.secret.data else self.secret.data)
