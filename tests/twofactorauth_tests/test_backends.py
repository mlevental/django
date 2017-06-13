from django.contrib.auth.models import User
from django.contrib.twofactorauth.backends import (
    BackupTokenBackend, TOTPBackend,
)
from django.contrib.twofactorauth.models import (
    BackupToken, BackupTokenDevice, TOTPDevice,
)
from django.contrib.twofactorauth.oath import TOTP, totp
from django.test import TestCase


class BaseAbstractOTPBackendTest:
    """
    A base class for testing 2FA backends that inherit from
    AbstractOTPBackend. Subclasses should define an initialize() method
    to initialize a 2FA backend, construct a user, a device and a token.
    """

    def setUp(self):
        self.initialize()

    def test_verify_response_with_token_and_user(self):
        self.assertEqual(self.backend.authenticate(self.token1, user=self.user1), self.device1)

    def test_verify_response_with_token_and_device(self):
        self.assertEqual(self.backend.authenticate(self.token1, device=self.device1), self.device1)


class TOTPBackendTest(BaseAbstractOTPBackendTest, TestCase):
    def initialize(self):
        self.backend = TOTPBackend()
        self.user1 = User.objects.create_user(username='testclient', password='password')
        self.device1 = TOTPDevice.objects.create(user=self.user1)
        self.token1 = totp(self.device1.bin_key)

    def test_saved_device_properties_after_successful_verification(self):
        device2 = TOTPDevice.objects.create(user=self.user1, tolerance=2)
        totp = TOTP(device2.bin_key, drift=2)
        token2 = totp.token()

        # before verification
        self.assertEqual(device2.drift, 0)
        self.assertEqual(device2.last_t, -1)

        # after verification
        self.assertEqual(TOTPBackend().authenticate(token2, device=device2), device2)
        device_from_db = TOTPDevice.objects.get(id=device2.id)
        self.assertEqual(device_from_db.drift, 2)
        self.assertEqual(device_from_db.last_t, totp.t())


class BackupTokenBackendTest(BaseAbstractOTPBackendTest, TestCase):
    def initialize(self):
        self.backend = BackupTokenBackend()
        self.user1 = User.objects.create_user(username='testclient', password='password')
        self.device1 = BackupTokenDevice.objects.create(user=self.user1)
        self.token1 = BackupToken.objects.create(device=self.device1, token='test12345').token

    def test_token_deleted_after_use(self):
        token2 = BackupToken.objects.create(device=self.device1, token='test54321').token
        self.assertTrue(BackupTokenBackend().authenticate(token2, device=self.device1))
        self.assertFalse(BackupToken.objects.filter(token='token54321').exists())
