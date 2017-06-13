from django.conf.urls import url
from django.contrib.twofactorauth.views import (
    FirstFactorLoginView, SecondFactorLoginView, TFADisableDoneView,
    TFADisableView,
)

app_name = 'tfa'

urlpatterns = [
    url(r'^first_factor_login/$', FirstFactorLoginView.as_view(), name='first_factor_login'),
    url(r'^second_factor_login/$', SecondFactorLoginView.as_view(), name='second_factor_login'),

    url(r'^tfa_disable/$', TFADisableView.as_view(), name='tfa_disable'),
    url(r'^tfa_disable/done/$', TFADisableDoneView.as_view(), name='tfa_disable_done'),
]
