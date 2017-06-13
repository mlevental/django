from django.contrib.auth import SESSION_KEY
from django.contrib.auth.models import User
from django.contrib.twofactorauth import DEVICE_ID_SESSION_KEY, has_tfa_enabled
from django.contrib.twofactorauth.models import BackupToken, BackupTokenDevice
from django.test import TestCase, override_settings
from django.urls import NoReverseMatch, reverse


@override_settings(
    LANGUAGES=[('en', 'English')],
    LANGUAGE_CODE='en',
    ROOT_URLCONF='twofactorauth_tests.urls',
    TFA_FORMS=[
        {'METHOD_NAME': 'BackupToken',
         'FORM_PATH': 'django.contrib.twofactorauth.forms.BackupTokenAuthenticationForm'
         },
    ],
    TFA_LOGIN_URL='tfa:first_factor_login',
)
class TFAViewsTestCase(TestCase):
    """
    Helper base class for the following test cases.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user1 = User.objects.create_user(username='testclient', password='password')
        cls.user2 = User.objects.create_user(username='testclient2', password='password2')
        cls.device1 = BackupTokenDevice.objects.create(user=cls.user1)
        cls.device2 = BackupTokenDevice.objects.create(user=cls.user2)
        BackupToken.objects.create(device=cls.device1, token='test12345')

    def first_factor_login(self, username='testclient', password='password'):
        response = self.client.post('/first_factor_login/', {
            'username': username,
            'password': password,
        })
        self.assertIn(SESSION_KEY, self.client.session)
        return response

    def second_factor_login(self, credentials=None):
        if credentials:
            response = self.client.post('/second_factor_login/', credentials)
        else:
            response = self.client.post('/second_factor_login/', {
                'token': 'test12345',
                'type': 'BackupToken',
            })
        self.assertIn(DEVICE_ID_SESSION_KEY, self.client.session)
        return response

    def two_factor_login(self):
        self.first_factor_login()
        self.second_factor_login()


class TFAViewsNamedURLTests(TFAViewsTestCase):
    def test_named_urls(self):
        "Named URLs should be reversible"
        expected_named_urls = [
            ('tfa:first_factor_login', [], {}),
            ('tfa:second_factor_login', [], {}),
            ('tfa:tfa_disable', [], {}),
            ('tfa:tfa_disable_done', [], {}),
        ]
        for name, args, kwargs in expected_named_urls:
            try:
                reverse(name, args=args, kwargs=kwargs)
            except NoReverseMatch:
                self.fail("Reversal of url named '%s' failed with NoReverseMatch" % name)


class FirstFactorRedirectAuthenticatedUser(TFAViewsTestCase):
    dont_redirect_url = '/first_factor_login/redirect_authenticated_user_default/'
    do_redirect_url = '/first_factor_login/redirect_authenticated_user/'

    def test_default(self):
        """Stay on the first factor login page by default."""
        self.first_factor_login()
        response = self.client.get(self.dont_redirect_url)
        self.assertEqual(response.status_code, 200)

    def test_guest(self):
        """If not authenticated, stay on the same page."""
        response = self.client.get(self.do_redirect_url)
        self.assertEqual(response.status_code, 200)

    def test_redirect(self):
        """If one factor authenticated, redirect to second factor login URL."""
        self.first_factor_login()
        response = self.client.get(self.do_redirect_url)
        self.assertRedirects(response, '/second_factor_login/?next=/accounts/profile/', fetch_redirect_response=False)

    def test_redirect_param_appended(self):
        """If one factor authenticated, redirect to second factor login URL with next param"""
        self.first_factor_login()
        url = self.do_redirect_url + '?next=/custom/'
        response = self.client.get(url)
        self.assertRedirects(response, '/second_factor_login/?next=/custom/')


class SecondFactorRedirectAuthenticatedUser(TFAViewsTestCase):
    dont_redirect_url = '/second_factor_login/redirect_authenticated_user_default/'
    do_redirect_url = '/second_factor_login/redirect_authenticated_user/'

    def test_default(self):
        """Stay on the second factor login page by default, if two factor authenticated."""
        self.two_factor_login()
        response = self.client.get(self.dont_redirect_url)
        self.assertEqual(response.status_code, 200)

    def test_guest(self):
        """If not authenticated, redirect to first factor URL."""
        response = self.client.get(self.do_redirect_url)
        self.assertRedirects(response, '/first_factor_login/', fetch_redirect_response=False)

    def test_one_factor_authenticated(self):
        """Stay on the second factor login page, if one factor authenticated."""
        self.first_factor_login()
        response = self.client.get(self.do_redirect_url)
        self.assertEqual(response.status_code, 200)

    def test_redirect(self):
        """If two factor authenticated, go to default redirect URL."""
        self.two_factor_login()
        response = self.client.get(self.do_redirect_url)
        self.assertRedirects(response, '/accounts/profile/', fetch_redirect_response=False)

    def test_redirect_param(self):
        """If next is specified as a GET parameter, go there."""
        self.two_factor_login()
        url = self.do_redirect_url + '?next=/custom/'
        response = self.client.get(url)
        self.assertRedirects(response, '/custom/', fetch_redirect_response=False)

    @override_settings(LOGIN_REDIRECT_URL='/custom/')
    def test_redirect_url(self):
        """If two factor authenticated, go to custom redirect URL."""
        self.two_factor_login()
        response = self.client.get(self.do_redirect_url)
        self.assertRedirects(response, '/custom/', fetch_redirect_response=False)


@override_settings(
    TFA_BACKENDS={'django.contrib.twofactorauth.backends.BackupTokenBackend'},
)
class TFADisableTest(TFAViewsTestCase):
    def setUp(self):
        self.device = BackupTokenDevice.objects.create(user=self.user1)
        BackupToken.objects.create(device=self.device, token='test123')

    def test_disabling_tfa_succeeds(self):
        self.first_factor_login()
        self.second_factor_login({'token': 'test123', 'type': 'BackupToken'})

        response = self.client.post('/tfa_disable/', {'disable': True})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/tfa_disable/done/')
        self.assertFalse(has_tfa_enabled(self.user1))

        response = self.client.get('/tfa_disable/')
        self.assertRedirects(response, '/first_factor_login/?next=/tfa_disable/', fetch_redirect_response=False)

    def test_disabling_tfa_fails(self):
        self.first_factor_login()
        self.second_factor_login({'token': 'test123', 'type': 'BackupToken'})

        response = self.client.post('/tfa_disable/', {'disable': False})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(has_tfa_enabled(self.user1))
