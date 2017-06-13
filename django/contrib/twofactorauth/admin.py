from django.contrib.admin import AdminSite
from django.contrib.twofactorauth.mixins import AdminSiteTFARequiredMixin


class AdminSiteTFARequired(AdminSiteTFARequiredMixin, AdminSite):
    pass
