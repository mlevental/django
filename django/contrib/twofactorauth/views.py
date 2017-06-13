from collections import OrderedDict

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, SuccessURLAllowedHostsMixin
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.twofactorauth import (
    get_form_classes, get_user_devices, two_factor_login,
)
from django.contrib.twofactorauth.decorators import tfa_required
from django.contrib.twofactorauth.forms import TFADisableForm
from django.http.response import HttpResponseRedirect
from django.shortcuts import resolve_url
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.http import is_safe_url
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, TemplateView


class FirstFactorLoginView(LoginView):
    """
    Display the login form for the first authenticaton factor and handle the
    authentication action.
    """
    template_name = 'registration/first_factor_login.html'

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        if self.redirect_authenticated_user and request.user.is_one_factor_authenticated:
            return HttpResponseRedirect(self.get_success_url())
        return super(FirstFactorLoginView, self).dispatch(request, *args, **kwargs)

    def get_success_url(self):
        # Ensure that an existing and safe success URL is used.
        success_url = self.success_url
        if not self._is_safe_url(success_url):
            success_url = reverse('tfa:second_factor_login')

        # Pass the redirection URL for the next view as an URL parameter.
        redirect_to = self.get_next_view_redirect_url()
        success_url += '?%s=%s' % (self.redirect_field_name, redirect_to)

        return success_url

    def get_next_view_redirect_url(self):
        return super(FirstFactorLoginView, self).get_success_url()

    def _is_safe_url(self, url):
        return is_safe_url(
            url=url,
            allowed_hosts=self.get_success_url_allowed_hosts(),
            require_https=self.request.is_secure(),
        )

    def get_context_data(self, **kwargs):
        context = super(FirstFactorLoginView, self).get_context_data()
        context[self.redirect_field_name] = self.get_next_view_redirect_url()
        return context


class SecondFactorLoginView(SuccessURLAllowedHostsMixin, TemplateView):
    """
    Display the form/s for the second authenticaton factor and handle the
    authentication action.
    """
    template_name = 'registration/second_factor_login.html'
    redirect_field_name = REDIRECT_FIELD_NAME
    redirect_authenticated_user = False
    extra_context = None

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        self.user = request.user
        if not self.user.is_one_factor_authenticated:
            return HttpResponseRedirect(self.get_permission_denied_url())
        elif self.redirect_authenticated_user and self.user.is_two_factor_authenticated:
            return HttpResponseRedirect(self.get_success_url())

        return super(SecondFactorLoginView, self).dispatch(request, *args, **kwargs)

    def get_permission_denied_url(self):
        return reverse('tfa:first_factor_login')

    def get_success_url(self):
        # Ensure that an existing and safe redirection URL is used.
        redirect_to = self.request.POST.get(
            self.redirect_field_name,
            self.request.GET.get(self.redirect_field_name, '')
        )
        url_is_safe = is_safe_url(
            url=redirect_to,
            allowed_hosts=self.get_success_url_allowed_hosts(),
            require_https=self.request.is_secure(),
        )
        if not url_is_safe:
            redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)
        return redirect_to

    def post(self, request, *args, **kwargs):
        forms = self.get_forms()
        form = forms[request.POST['type']]
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(forms)

    def form_invalid(self, forms):
        return self.render_to_response(self.get_context_data(forms=forms, ))

    def get_form_kwargs(self):
        return {
            'user': self.user,
            'request': self.request,
        }

    def get_form_classes(self):
        return get_form_classes()

    def get_forms(self):
        """Return the forms in the order as specified in TFA_FORMS."""
        kwargs = self.get_form_kwargs()
        form_classes = self.get_form_classes()

        if self.request.method == 'GET':
            forms = OrderedDict()
            for method_name, form in form_classes.items():
                forms[method_name] = form(**kwargs)
        else:
            method = self.request.POST['type']
            forms = OrderedDict()
            for method_name, form in form_classes.items():
                if method_name != method:
                    forms[method_name] = form(**kwargs)
            forms[method] = form_classes[method](self.request.POST, **kwargs)

        return forms

    def get_context_data(self, **kwargs):
        context = super(SecondFactorLoginView, self).get_context_data(**kwargs)
        current_site = get_current_site(self.request)
        context.update({
            self.redirect_field_name: self.get_success_url(),
            'site': current_site,
            'site_name': current_site.name,
            'user': self.user,
            'forms': self.get_forms(),
        })
        if self.extra_context is not None:
            context.update(self.extra_context)
        return context

    def form_valid(self, form):
        two_factor_login(self.request, form.get_device())
        return HttpResponseRedirect(self.get_success_url())


class TFADisableView(FormView):
    template_name = 'admin/tfa_disable.html'
    form_class = TFADisableForm
    success_url = reverse_lazy('tfa:tfa_disable_done')
    title = _('Disable TFA')

    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    @method_decorator(tfa_required)
    def dispatch(self, *args, **kwargs):
        return super(TFADisableView, self).dispatch(*args, **kwargs)

    def form_valid(self, form):
        for device in get_user_devices(self.request.user):
            device.delete()
        return super(TFADisableView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        context = super(TFADisableView, self).get_context_data(**kwargs)
        context['title'] = self.title
        return context


class TFADisableDoneView(TemplateView):
    template_name = 'admin/tfa_disable_done.html'
    title = _('TFA disabled')

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(TFADisableDoneView, self).dispatch(*args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(TFADisableDoneView, self).get_context_data(**kwargs)
        context['title'] = self.title
        return context
