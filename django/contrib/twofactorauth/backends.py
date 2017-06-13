import time

from django.conf import settings
from django.contrib.twofactorauth.models import BackupTokenDevice, TOTPDevice
from django.contrib.twofactorauth.oath import TOTP


class AbstractOTPBackend:
    """
    An abstract base class for OTP backends.
    Subclasses must implement get_user_devices() and verify_token().
    """

    def authenticate(self, token, user=None, device=None):
        """
        Authenticate given a token and either a user or user's device.
        If the token is valid, return the TFA device used for successful authentication.
        """
        if device:
            return device if self.verify_token(token, device) else None
        else:
            for device in self.get_user_devices(user):
                if self.verify_token(token, device):
                    return device
            return None


class TOTPBackend(AbstractOTPBackend):
    def get_user_devices(self, user):
        return [] if user.is_anonymous else TOTPDevice.objects.filter(user=user)

    def verify_token(self, token, device):
        TOTP_SYNC = getattr(settings, 'TOTP_SYNC', True)

        key = device.bin_key

        totp = TOTP(key, device.step, device.t0, device.digits, device.drift)
        totp.time = time.time()

        verified = totp.verify(token, device.tolerance, device.last_t + 1)
        if verified:
            device.last_t = totp.t()
            if TOTP_SYNC:
                device.drift = totp.drift
            device.save()

        return verified


class BackupTokenBackend(AbstractOTPBackend):
    def get_user_devices(self, user):
        return [] if user.is_anonymous else BackupTokenDevice.objects.filter(user=user)

    def verify_token(self, token, device):
        try:
            match = next(device.token_set.filter(token=token).iterator())
            match.delete()
        except StopIteration:
            match = None

        return (match is not None)
