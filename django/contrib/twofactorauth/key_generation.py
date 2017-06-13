from __future__ import (
    absolute_import, division, print_function, unicode_literals,
)

from binascii import hexlify
from os import urandom

from django.utils.encoding import force_text


def random_hex(length=20):
    """
    Returns a string of random bytes encoded as hex. This uses
    :func:`os.urandom`, so it should be suitable for generating cryptographic
    keys.
    """
    return hexlify(urandom(length))


def default_key():
    return force_text(random_hex(20))
