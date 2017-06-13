from tests.auth_tests.test_mixins import EmptyResponseView

from django.contrib.auth import models
from django.contrib.auth.models import AnonymousUser
from django.contrib.twofactorauth.models import BackupTokenDevice
from django.test import RequestFactory, TestCase, override_settings


@override_settings(
    ROOT_URLCONF='twofactorauth_tests.urls',
    TFA_LOGIN_URL='tfa:first_factor_login',
)
class TFARequiredMixinTest(TestCase):
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.user = models.User.objects.create(username='testclient', password='password')
        cls.device = BackupTokenDevice.objects.create(user=cls.user)

    def test_tfa_required(self):
        from django.contrib.twofactorauth.mixins import TFARequiredMixin

        class TFARequiredView(TFARequiredMixin, EmptyResponseView):
            pass

        view = TFARequiredView.as_view()

        request = self.factory.get('/rand')
        request.user = AnonymousUser()
        response = view(request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual('/first_factor_login/?next=/rand', response.url)

        request = self.factory.get('/rand')
        request.user = self.user
        request.user.tfa_device = self.device
        response = view(request)
        self.assertEqual(response.status_code, 200)
