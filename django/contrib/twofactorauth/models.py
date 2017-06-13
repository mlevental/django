from base64 import b32encode
from binascii import unhexlify
from urllib.parse import quote, urlencode

from django.conf import settings
from django.contrib.auth.models import update_last_login
from django.contrib.twofactorauth import tfa_successful
from django.contrib.twofactorauth.key_generation import default_key
from django.contrib.twofactorauth.validators import key_validator
from django.db import models
from django.utils.six import string_types


class Device(models.Model):
    user = models.ForeignKey(
        getattr(settings, 'AUTH_USER_MODEL', 'auth.User'),
        help_text="The user that this device was setup for.",
        on_delete=models.CASCADE,
    )

    class Meta:
        abstract = True

    @property
    def import_path(self):
        return '{0}.{1}'.format(self.__module__, self.__class__.__name__)

    @property
    def persistent_id(self):
        return '{0}/{1}'.format(self.import_path, self.id)


class TOTPDevice(Device):
    key = models.CharField(
        max_length=128,
        validators=[key_validator],
        default=default_key,
        help_text="A hex-encoded secret key of up to 64 bytes.",
    )
    step = models.PositiveSmallIntegerField(default=30, help_text="The time step in seconds.")
    t0 = models.BigIntegerField(default=0, help_text="The Unix time at which to begin counting steps.")
    digits = models.PositiveSmallIntegerField(default=6, help_text="The number of digits to expect in a token.")
    tolerance = models.PositiveSmallIntegerField(
        default=1,
        help_text="The number of time steps in the past or future to allow.",
    )
    drift = models.SmallIntegerField(
        default=0,
        help_text="The number of time steps the prover is known to deviate from our clock.",
    )
    last_t = models.BigIntegerField(
        default=-1,
        help_text="The t value of the latest verified token. The next token must be at a higher time step.",
    )

    @property
    def bin_key(self):
        """
        The secret key as a binary string.
        """
        return unhexlify(self.key.encode())

    @property
    def config_url(self):
        """
        A URL for configuring Google Authenticator or similar.
        See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
        """
        label = self.user.get_username()
        params = {
            'secret': b32encode(self.bin_key),
            'algorithm': 'SHA1',
            'digits': self.digits,
            'period': self.step,
        }

        issuer = getattr(settings, 'TOTP_ISSUER', None)
        if isinstance(issuer, string_types) and (issuer != ''):
            issuer = issuer.replace(':', '')
            params['issuer'] = issuer
            label = '{}:{}'.format(issuer, label)

        url = 'otpauth://totp/{}?{}'.format(quote(label), urlencode(params))

        return url


class BackupTokenDevice(Device):
    pass


class BackupToken(models.Model):
    device = models.ForeignKey(BackupTokenDevice, related_name='token_set', on_delete=models.CASCADE)
    token = models.CharField(max_length=16, db_index=True)


tfa_successful.connect(update_last_login)
