from tests.twofactorauth_tests.test_views import TFAViewsTestCase

from django.conf import settings
from django.contrib.twofactorauth.decorators import tfa_required
from django.test import override_settings


@override_settings(TFA_LOGIN_URL='/tfa_login/')
class TFARequiredTestCase(TFAViewsTestCase):
    """
    Tests the tfa_required decorator
    """

    def testCallable(self):
        """
        tfa_required is assignable to callable objects.
        """
        class CallableView:
            def __call__(self, *args, **kwargs):
                pass

        tfa_required(CallableView())

    def testView(self):
        """
        tfa_required is assignable to normal views.
        """
        def normal_view(request):
            pass

        tfa_required(normal_view)

    def testTFARequired(self, view_url='/tfa_required/', tfa_login_url=None):
        """
        tfa_required works on a simple view wrapped in a tfa_required
        decorator.
        """
        if tfa_login_url is None:
            tfa_login_url = settings.TFA_LOGIN_URL
        response = self.client.get(view_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(tfa_login_url, response.url)
        self.two_factor_login()
        response = self.client.get(view_url)
        self.assertEqual(response.status_code, 200)

    def testTFARequiredNextUrl(self):
        """
        tfa_required works on a simple view wrapped in a tfa_required
        decorator with a tfa_login_url set.
        """
        self.testTFARequired(view_url='/tfa_required_login_url/', tfa_login_url='/somewhere/')
