from django.contrib.auth.models import User
from django.contrib.twofactorauth.forms import (
    BackupTokenAuthenticationForm, TOTPAuthenticationForm,
)
from django.contrib.twofactorauth.models import (
    BackupToken, BackupTokenDevice, TOTPDevice,
)
from django.contrib.twofactorauth.oath import totp
from django.test import TestCase


class TestDataMixin:
    @classmethod
    def setUpTestData(cls):
        cls.user1 = User.objects.create_user(username='testclient', password='password')
        cls.user2 = User.objects.create_user(username='inactive', password='password', is_active=False)
        cls.totp_device1 = TOTPDevice.objects.create(user=cls.user1)
        cls.totp_device2 = TOTPDevice.objects.create(user=cls.user2)
        cls.backup_token_device1 = BackupTokenDevice.objects.create(user=cls.user1)
        cls.backup_token_device2 = BackupTokenDevice.objects.create(user=cls.user2)
        BackupToken.objects.create(device=cls.backup_token_device1, token='test12345')
        BackupToken.objects.create(device=cls.backup_token_device2, token='test54321')


class TOTPAuthenticatonFormTest(TestDataMixin, TestCase):
    def test_valid_token(self):
        data = {'token': totp(self.totp_device1.bin_key)}
        form = TOTPAuthenticationForm(user=self.user1, data=data)
        self.assertTrue(form.is_valid())
        self.assertEqual(form.non_field_errors(), [])

    def test_invalid_token(self):
        form = TOTPAuthenticationForm(user=self.user1, data={'token': 1234567})
        self.assertFalse(form.is_valid())
        self.assertEqual(form.non_field_errors(), [form.INVALID_TOKEN_MESSAGE])


class BackupTokenAuthenticatonFormTest(TestDataMixin, TestCase):
    def test_valid_token(self):
        form = BackupTokenAuthenticationForm(user=self.user1, data={'token': 'test12345'})
        self.assertTrue(form.is_valid())
        self.assertEqual(form.non_field_errors(), [])

    def test_invalid_token(self):
        form = BackupTokenAuthenticationForm(user=self.user1, data={'token': 'invalid token'})
        self.assertFalse(form.is_valid())
        self.assertEqual(form.non_field_errors(), [form.INVALID_TOKEN_MESSAGE])
