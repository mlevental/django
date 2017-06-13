from tests.twofactorauth_tests.test_views import TFAViewsTestCase

from django.contrib.auth import SESSION_KEY
from django.contrib.auth.models import User
from django.contrib.twofactorauth import DEVICE_ID_SESSION_KEY
from django.contrib.twofactorauth.models import BackupToken, BackupTokenDevice
from django.urls import reverse


class AdminSiteTFATest(TFAViewsTestCase):
    @classmethod
    def setUpTestData(cls):
        # users
        cls.superuser = User.objects.create_superuser(username='super', password='password', email='super@test.com')
        cls.nostaffuser = User.objects.create_user(username='nostaff', password='password')

        # TFA devices
        cls.device1 = BackupTokenDevice.objects.create(user=cls.superuser)
        cls.device2 = BackupTokenDevice.objects.create(user=cls.nostaffuser)
        BackupToken.objects.create(device=cls.device1, token='test12345')
        BackupToken.objects.create(device=cls.device2, token='test54321')

        # login POST dicts
        cls.super_first_factor_credentials = {
            'username': 'super',
            'password': 'password',
        }
        cls.super_second_factor_credentials = {
            'token': 'test12345',
            'type': 'BackupToken',
        }
        cls.nostaff_first_factor_credentials = {
            'username': 'nostaff',
            'password': 'password',
        }
        cls.nostaff_second_factor_credentials = {
            'token': 'test54321',
            'type': 'BackupToken',
        }

        # admin urls
        cls.index_url = reverse('admin:index')
        cls.login_url = reverse('admin:login')
        cls.login_url_with_next = '%s?next=%s' % (reverse('admin:login'), reverse('admin:index'))

    def test_login(self):
        response = self.client.get(self.index_url)
        self.assertRedirects(response, self.login_url_with_next)

        first_factor_login = self.client.post(self.login_url_with_next, self.super_first_factor_credentials)
        self.assertIn(SESSION_KEY, self.client.session)
        self.assertRedirects(first_factor_login, self.login_url_with_next)

        second_factor_login = self.client.post(self.login_url_with_next, self.super_second_factor_credentials)
        self.assertIn(DEVICE_ID_SESSION_KEY, self.client.session)
        self.assertRedirects(second_factor_login, self.index_url)

    def test_first_factor_authenticated(self):
        self.first_factor_login(**self.super_first_factor_credentials)

        # GET requests to /admin/index should be redirected to /admin/login/ with the redirect parameter appended.
        response = self.client.get(self.index_url)
        self.assertRedirects(response, self.login_url_with_next)

        # When accessing the admin login page the redirect parameter should be appended.
        response = self.client.get(self.login_url)
        self.assertTrue(response.status_code, 200)
        self.assertEqual(response.context['next'], self.index_url)

    def test_two_factor_authenticated(self):
        self.first_factor_login(**self.super_first_factor_credentials)
        self.second_factor_login(self.super_second_factor_credentials)

        # The admin index page is loaded without redirects.
        response = self.client.get(self.index_url)
        self.assertTrue(response.status_code, 200)

        # When accessing the admin login page the admin index page should be loaded.
        response = self.client.get(self.login_url)
        self.assertRedirects(response, self.index_url)
