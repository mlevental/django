from django.conf.urls import include, url
from django.contrib.twofactorauth import views
from django.contrib.twofactorauth.admin import AdminSiteTFARequired
from django.contrib.twofactorauth.decorators import tfa_required
from django.http import HttpResponse

site = AdminSiteTFARequired(name="admin")


def custom_page(request):
    return HttpResponse()


urlpatterns = [
    url(r'', include('django.contrib.twofactorauth.urls', namespace='tfa')),

    url(r'^first_factor_login/redirect_authenticated_user_default/$', views.FirstFactorLoginView.as_view()),
    url(r'^first_factor_login/redirect_authenticated_user/$',
        views.FirstFactorLoginView.as_view(redirect_authenticated_user=True)),

    url(r'^second_factor_login/redirect_authenticated_user_default/$', views.SecondFactorLoginView.as_view()),
    url(r'^second_factor_login/redirect_authenticated_user/$',
        views.SecondFactorLoginView.as_view(redirect_authenticated_user=True)),

    url(r'^custom/$', custom_page),

    url(r'^tfa_required/$', tfa_required(custom_page)),
    url(r'^tfa_required_login_url/$', tfa_required(custom_page, tfa_login_url='/somewhere/')),

    url(r'^admin/', site.urls),
]
