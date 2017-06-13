from urllib.parse import parse_qsl, urlparse

from django.contrib.auth.models import User
from django.contrib.twofactorauth.models import (
    BackupToken, BackupTokenDevice, TOTPDevice,
)
from django.test import TestCase, override_settings


class TOTPDeviceTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='testclient', password="testpassword")
        cls.device = TOTPDevice.objects.create(user=cls.user, key='e94694ea93cba374e064712fa65cdded6404f162')

    def assertUrlContainsParams(self, config_url, expected_params_dict):
        result_params_str = urlparse(config_url).query
        result_params_dict = dict(parse_qsl(result_params_str))
        for key in expected_params_dict:
            self.assertEqual(expected_params_dict[key], result_params_dict[key])

    def test_import_path(self):
        self.assertEqual(self.device.import_path, 'django.contrib.twofactorauth.models.TOTPDevice')

    def test_persistent_id(self):
        self.assertEqual(self.device.persistent_id, 'django.contrib.twofactorauth.models.TOTPDevice/1')

    def test_config_url_without_issuer(self):
        config_url = self.device.config_url
        self.assertTrue(config_url.startswith("otpauth://totp/testclient?"))
        expected_params_dict = {
            'secret': '5FDJJ2UTZORXJYDEOEX2MXG55VSAJ4LC',
            'algorithm': 'SHA1',
            'digits': '6',
            'period': '30',
        }
        self.assertUrlContainsParams(config_url, expected_params_dict)

    @override_settings(TOTP_ISSUER='Test Company')
    def test_config_url_with_issuer(self):
        config_url = self.device.config_url
        self.assertTrue(config_url.startswith("otpauth://totp/Test%20Company%3Atestclient?"))
        expected_params_dict = {
            'secret': '5FDJJ2UTZORXJYDEOEX2MXG55VSAJ4LC',
            'algorithm': 'SHA1',
            'digits': '6',
            'period': '30',
            'issuer': 'Test Company'
        }
        self.assertUrlContainsParams(config_url, expected_params_dict)

    @override_settings(TOTP_ISSUER=':Test:Company:')
    def test_config_url_issuer_with_colons(self):
        config_url = self.device.config_url
        self.assertTrue(config_url.startswith("otpauth://totp/TestCompany%3Atestclient?"))
        expected_params_dict = {
            'secret': '5FDJJ2UTZORXJYDEOEX2MXG55VSAJ4LC',
            'algorithm': 'SHA1',
            'digits': '6',
            'period': '30',
            'issuer': 'TestCompany'
        }
        self.assertUrlContainsParams(config_url, expected_params_dict)


class BackupTokenDeviceTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='testclient', password="testpassword")
        cls.device = BackupTokenDevice.objects.create(user=cls.user)

    def test_import_path(self):
        self.assertEqual(self.device.import_path, 'django.contrib.twofactorauth.models.BackupTokenDevice')

    def test_persistent_id(self):
        self.assertEqual(self.device.persistent_id, 'django.contrib.twofactorauth.models.BackupTokenDevice/1')

    def test_token_cascade_delete(self):
        device = BackupTokenDevice.objects.create(user=self.user)
        token = BackupToken.objects.create(device=device, token='testtoken123')
        self.assertTrue(BackupToken.objects.filter(id=token.id).exists())

        token.delete()
        self.assertFalse(BackupToken.objects.filter(id=token.id).exists())
