from collections import OrderedDict

from django.conf import settings
from django.contrib.auth import load_backend
from django.contrib.twofactorauth.signals import tfa_successful
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

DEVICE_ID_SESSION_KEY = 'tfa_device_id'


def load_device(persistent_id):
    try:
        device_path, device_id = persistent_id.rsplit('/', 1)
        device_class = import_string(device_path)
        device = device_class.objects.get(id=device_id)
    except Exception:
        device = None

    return device


def get_form_classes():
    """
    Return an ordered dictionary with the TFA method name as the key and
    the form class as the value.
    """
    form_classes = OrderedDict()

    for entry in settings.TFA_FORMS:
        form_path = entry.get('FORM_PATH', None)
        method_name = entry.get('METHOD_NAME', None)
        if form_path and method_name:
            form_class = import_string(form_path)
            form_classes[method_name] = form_class

    if not form_classes:
        raise ImproperlyConfigured(
            'No second factor authentication forms have been defined. Does '
            'TFA_FORMS contain dictionaries with the keys METHOD_NAME and FORM_PATH?'
        )

    return form_classes


def two_factor_login(request, device):
    """
    Persist the TFA device in the session.
    """
    user = getattr(request, 'user', None)

    if (user is not None) and (device is not None) and (device.user_id == user.id):
        request.session[DEVICE_ID_SESSION_KEY] = device.persistent_id
        request.user.tfa_device = device
        tfa_successful.send(sender=user.__class__, request=request, user=user, device=device)


def get_tfa_backends():
    backends = []

    for backend_path in settings.TFA_BACKENDS:
        backend = load_backend(backend_path)
        backends.append(backend)

    if not backends:
        raise ImproperlyConfigured(
            'No second factor authentication backends have been defined. Does '
            'TFA_BACKENDS contain anything?'
        )

    return backends


def get_user_devices(user):
    devices = []

    for backend in get_tfa_backends():
        for device in backend.get_user_devices(user):
            devices.append(device)

    return devices


def has_tfa_enabled(user):
    for backend in get_tfa_backends():
        if backend.get_user_devices(user):
            return True
    return False


def is_tfa_required(user):
    is_tfa_optional = getattr(settings, 'TFA_OPTIONAL', True)
    return not is_tfa_optional or (is_tfa_optional and has_tfa_enabled(user))
