from __future__ import (
    absolute_import, division, print_function, unicode_literals,
)

import hmac
from hashlib import sha1
from struct import pack
from time import time

from django.utils import six

if six.PY3:
    iterbytes = iter
else:
    def iterbytes(buf):
        return (ord(b) for b in buf)


def hotp(key, counter, digits=6):
    """
    Return the HOTP token.

    The implementation is based on the HOTP algorithm from RFC 4226
    at http://tools.ietf.org/html/rfc4226#section-5.
    """
    msg = pack(b'>Q', counter)
    hs = hmac.new(key, msg, sha1).digest()
    hs = list(iterbytes(hs))

    offset = hs[19] & 0x0f
    bin_code = (hs[offset] & 0x7f) << 24 | hs[offset + 1] << 16 | hs[offset + 2] << 8 | hs[offset + 3]
    return '{hotp:0{digits}d}'.format(hotp=bin_code % 10 ** digits, digits=digits)

    return hotp


def totp(key, step=30, t0=0, digits=6, drift=0):
    """
    Return the TOTP token.

    The implementation is based on the TOTP algorithm from RFC 6238
    at http://tools.ietf.org/html/rfc6238#section-4.
    """
    return TOTP(key, step, t0, digits, drift).token()


class TOTP(object):
    """
    An alternate TOTP interface.

    This provides access to intermediate steps of the computation. This is a
    living object: the return values of `t` and `token` will change along
    with other properties and with the passage of time.
    """

    def __init__(self, key, step=30, t0=0, digits=6, drift=0):
        self.key = key
        self.step = step
        self.t0 = t0
        self.digits = digits
        self.drift = drift
        self._time = None

    def token(self):
        """Return the computed TOTP token."""
        return hotp(self.key, self.t(), digits=self.digits)

    def t(self):
        """Return the computed time step."""
        return ((int(self.time) - self.t0) // self.step) + self.drift

    @property
    def time(self):
        """
        Return The current time.

        By default, this returns time.time() each time it is accessed. If you
        want to generate a token at a specific time, you can set this property
        to a fixed value instead. Deleting the value returns it to its 'live'
        state.
        """
        return self._time if (self._time is not None) else time()

    @time.setter
    def time(self, value):
        self._time = value

    @time.deleter
    def time(self):
        self._time = None

    def verify(self, token, tolerance=0, min_t=None):
        """
        A high-level verification helper.

        Iff this returns True, `self.drift` will be updated to reflect the
        drift value that was necessary to match the token.
        """
        drift_orig = self.drift
        verified = False

        for offset in range(-tolerance, tolerance + 1):
            self.drift = drift_orig + offset

            if (min_t is not None and self.t() < min_t) or self.t() < 0:
                continue
            elif self.token() == token:
                verified = True
                break
        else:
            self.drift = drift_orig

        return verified
