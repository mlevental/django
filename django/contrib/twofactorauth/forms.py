from django import forms
from django.contrib.twofactorauth.backends import (
    BackupTokenBackend, TOTPBackend,
)
from django.utils.translation import ugettext_lazy as _


class AbstractSecondFactorAuthenticationForm(forms.Form):
    """
    An abstract base class for forms implementing the second authentication
    factor. Subclasses must set device_cache to the TFA device used for
    successful authentication.
    """
    INACTIVE_USER_MESSAGE = _("This account is inactive.")

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        self.request = kwargs.pop('request', None)
        self.device_cache = None
        super(AbstractSecondFactorAuthenticationForm, self).__init__(*args, **kwargs)

    def get_device(self):
        return self.device_cache


class AbstractOTPAuthenticationForm(AbstractSecondFactorAuthenticationForm):
    """
    An abstract base class for OTP authentication forms.
    Subclasses must implement get_backend().
    """
    INVALID_TOKEN_MESSAGE = _("That token is invalid.")

    def clean(self):
        token = self.cleaned_data['token']

        if token:
            self.device_cache = self.get_backend().authenticate(token, self.user)
            if self.device_cache is None:
                raise forms.ValidationError(
                    self.INVALID_TOKEN_MESSAGE,
                    code='invalid_token',
                )

        return self.cleaned_data


class TOTPAuthenticationForm(AbstractOTPAuthenticationForm):
    token = forms.CharField(label=_("Token"))

    def get_backend(self):
        return TOTPBackend()


class BackupTokenAuthenticationForm(AbstractOTPAuthenticationForm):
    token = forms.CharField(
        label=_("Backup token"),
        max_length=16,
        widget=forms.TextInput(attrs={'autocomplete': 'off'})
    )

    def get_backend(self):
        return BackupTokenBackend()


class TFADisableForm(forms.Form):
    disable = forms.BooleanField(label=_("Yes, I am sure"))
