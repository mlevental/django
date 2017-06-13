from django.dispatch import Signal

tfa_successful = Signal(providing_args=['request', 'user', 'device'])
