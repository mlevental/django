from time import time

from django.contrib.twofactorauth.oath import TOTP, hotp
from django.test import TestCase


class TestOATHTestValues(TestCase):
    def test_hotp(self):
        """
        Validate the test values from RFC 4226 at https://tools.ietf.org/html/rfc4226#page-32
        """
        hotp_values = [
            '755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'
        ]
        key = b'12345678901234567890'
        for counter in range(10):
            self.assertEqual(hotp(key, counter), hotp_values[counter])

    def test_totp(self):
        """
        Validate the test vectors from RFC 6238 at https://tools.ietf.org/html/rfc6238#appendix-B
        """
        test_vectors = [
            (59, '94287082'), (1111111109, '07081804'), (1111111111, '14050471'), (1234567890, '89005924'),
            (2000000000, '69279037'), (20000000000, '65353130')
        ]
        key = b'12345678901234567890'
        for vector in test_vectors:
            totp = TOTP(key, digits=8)
            totp.time = vector[0]
            self.assertEqual(totp.token(), vector[1])


class TestTOTP(TestCase):
    def setUp(self):
        self.totp = TOTP(key=b'12345678901234567890')
        self.totp.time = 0

    def test_totp_time_step(self):
        # First time step is 0
        self.assertEqual(self.totp.t(), 0)

        # Next time step is 1
        self.totp.time = 30
        self.assertEqual(self.totp.t(), 1)

    def test_totp_tolerance(self):
        # Set the time so that a valid token for the previous step exists
        self.totp.time = 30

        # Only the token for the current time step is valid
        self.assertTrue(self.totp.verify('287082'))
        self.assertFalse(self.totp.verify('755224'))
        self.assertFalse(self.totp.verify('359152'))

        # Aditionally the tokens for the previous and next time step are valid
        self.assertTrue(self.totp.verify('287082', tolerance=1))
        self.assertTrue(self.totp.verify('755224', tolerance=1))
        self.totp.drift = 0
        self.assertTrue(self.totp.verify('359152', tolerance=1))

    def test_totp_minimum_accepted_time_step(self):
        # The token for the time step 0 is valid
        self.assertTrue(self.totp.verify('755224'))

        # The token for the time step 0 is invalid if only tokens for the time step 1 or above are accepted
        self.assertFalse(self.totp.verify('755224', min_t=1))
        self.assertFalse(self.totp.verify('755224', tolerance=1, min_t=1))

        # The token for the time step 1 is valid
        self.assertTrue(self.totp.verify('287082', tolerance=1, min_t=1))

    def test_totp_drift(self):
        """
        When a clock drift occurs the drift parameter is set only for valid tokens
        """

        self.assertTrue(self.totp.verify('287082', tolerance=1))
        self.assertEqual(self.totp.drift, 1)

        self.totp.drift = 0
        self.assertFalse(self.totp.verify('287082', tolerance=1, min_t=2))
        self.assertEqual(self.totp.drift, 0)

    def test_starting_time_counting_time_steps(self):
        """
        The computed time step takes the starting time into account
        """
        del self.totp.time
        self.totp.t0 = int(time()) - 60
        self.assertEqual(self.totp.t(), 2)
