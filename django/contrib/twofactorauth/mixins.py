from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.mixins import AccessMixin
from django.contrib.twofactorauth.views import (
    FirstFactorLoginView, SecondFactorLoginView,
)
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.encoding import force_text
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache


class TFARequiredMixin(AccessMixin):
    """Verify that the current user is authenticated with two factors."""

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_two_factor_authenticated:
            return self.handle_no_permission()
        return super(TFARequiredMixin, self).dispatch(request, *args, **kwargs)

    def get_login_url(self):
        login_url = self.login_url or settings.TFA_LOGIN_URL
        if not login_url:
            raise ImproperlyConfigured(
                '{0} is missing the login_url attribute. Define {0}.login_url, settings.TFA_LOGIN_URL, or override '
                '{0}.get_login_url().'.format(self.__class__.__name__)
            )
        return force_text(login_url)


class AdminSiteTFARequiredMixin(object):
    def has_permission(self, request):
        """
        Returns True if the given HttpRequest has permission to view
        *at least one* page in the admin site and is two factor authenticated.
        """
        user = request.user
        return super(AdminSiteTFARequiredMixin, self).has_permission(request) and user.is_two_factor_authenticated

    @never_cache
    def login(self, request, extra_context=None):
        if request.method == 'GET' and self.has_permission(request):
            # Already logged-in, redirect to admin index
            index_path = reverse('admin:index', current_app=self.name)
            return HttpResponseRedirect(index_path)

        context = self._get_context(request, extra_context)
        request.current_app = self.name

        user = request.user
        if user.is_one_factor_authenticated and super(AdminSiteTFARequiredMixin, self).has_permission(request):
            defaults = {
                'extra_context': context,
                'template_name': self.login_template or 'admin/second_factor_login.html',
            }
            return SecondFactorLoginView.as_view(**defaults)(request)
        else:
            from django.contrib.admin.forms import AdminAuthenticationForm
            defaults = {
                'extra_context': context,
                'authentication_form': self.login_form or AdminAuthenticationForm,
                'template_name': self.login_template or 'admin/login.html',
                'success_url': reverse('admin:login', current_app=self.name),
            }
            return FirstFactorLoginView.as_view(**defaults)(request)

    def _get_context(self, request, extra_context):
        context = dict(
            self.each_context(request),
            title=_('Log in'),
            app_path=request.get_full_path(),
            username=request.user.get_username(),
        )

        if REDIRECT_FIELD_NAME not in request.GET and REDIRECT_FIELD_NAME not in request.POST:
            context[REDIRECT_FIELD_NAME] = reverse('admin:index', current_app=self.name)
        context.update(extra_context or {})

        return context
