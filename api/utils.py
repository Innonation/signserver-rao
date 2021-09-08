# -*- coding: utf-8 -*-
import hmac
import json
import logging
import os
import random

from api.models import User, Entity
from signserver.classes.choices import input_hmac_parameters

LOG = logging.getLogger(__name__)


def generate_pin():
    pin = ''
    for x in range(6):
        pin += str(random.randint(0, 9))
    return pin



def check_hmac(username, api_data):
    user = User.objects.filter(username=username.upper()).last()
    data = json.loads(api_data.replace("\'", "\""))
    hmac_parameters = data.pop('hmac_parameters')
    param_string = ''
    for k in input_hmac_parameters:
        param_string += data[k] if k in data.keys() else ''
    calculated_hmac = hmac.new(user.pin.encode(), param_string.replace(" ", "").encode(), "SHA256").hexdigest()
    if str(hmac_parameters).upper() == str(calculated_hmac).upper():
        return True
    return False


def check_authtoken(username, entity, parameter, hmac_params):
    entity = Entity.objects.filter(entity=entity.upper()).last()
    if entity:
        user = User.objects.filter(username=username.upper(), entity=entity).last()
        if user:
            try:
                message = username + parameter
                calculated_hmac = hmac.new(user.pin.encode(), message.encode(), "SHA256").hexdigest()
                if str(hmac_params).upper() == str(calculated_hmac).upper():
                    return True
            except Exception as e:
                LOG.error("Exception: {}".format(str(e)))
        return False


def check_pin(username, hmac_params):
    user = User.objects.filter(username=username.upper()).last()
    if user:
        try:
            calculated_hmac = hmac.new(user.pin.encode(), username.encode(), "SHA256").hexdigest()
            if str(hmac_params).upper() == str(calculated_hmac).upper():
                return True
        except Exception as e:
            LOG.error("Exception: {}".format(str(e)))
    return False


def generate_file_name():
    file_name = "".join(
        [random.choice("ABCDEFGHIJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789") for i in range(16)]) + ".pem"
    while os.path.exists(file_name):
        file_name = "".join(
            [random.choice("ABCDEFGHIJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789") for i in
             range(16)]) + ".pem"
    return file_name
