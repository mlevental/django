from __future__ import (
    absolute_import, division, print_function, unicode_literals,
)

from binascii import unhexlify

from django.core.exceptions import ValidationError
from django.utils import six


def hex_validator(length=0):
    """
    Returns a function to be used as a model validator for a hex-encoded
    CharField.

    If `length` is greater than 0, validation will fail unless the
    decoded value is exactly this number of bytes.
    """

    def _validator(value):
        try:
            if isinstance(value, six.text_type):
                value = value.encode()

            unhexlify(value)
        except Exception:
            raise ValidationError('{0} is not valid hex-encoded data.'.format(value))

        if (length > 0) and (len(value) != length * 2):
            raise ValidationError('{0} does not represent exactly {1} bytes.'.format(value, length))

    return _validator


def key_validator(value):
    return hex_validator()(value)
