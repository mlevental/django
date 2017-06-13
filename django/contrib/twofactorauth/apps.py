from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _


class AuthConfig(AppConfig):
    name = 'django.contrib.twofactorauth'
    verbose_name = _("Two Factor Authentication")
