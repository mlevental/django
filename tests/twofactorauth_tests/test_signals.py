from tests.twofactorauth_tests.test_views import TFAViewsTestCase

from django.contrib.twofactorauth import tfa_successful


class SignalTestCase(TFAViewsTestCase):
    def listener_tfa(self, device, **kwargs):
        self.tfa_successful.append(device)

    def setUp(self):
        """Connect the listener and reset the TFA successful counter"""
        self.tfa_successful = []
        tfa_successful.connect(self.listener_tfa)

    def tearDown(self):
        """Disconnect the listener"""
        tfa_successful.disconnect(self.listener_tfa)

    def test_tfa_successful(self):
        self.two_factor_login()
        self.assertEqual(len(self.tfa_successful), 1)
        self.assertEqual(self.tfa_successful[0], self.device1)

    def test_tfa_failed(self):
        self.first_factor_login()
        with self.assertRaises(AssertionError):
            self.second_factor_login({
                'token': 'wrong',
                'type': 'BackupToken',
            })
        self.assertEqual(len(self.tfa_successful), 0)
