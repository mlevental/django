from django.contrib.twofactorauth import DEVICE_ID_SESSION_KEY, load_device
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject


class TFAMiddleware(MiddlewareMixin):
    def process_request(self, request):
        user = getattr(request, 'user', None)
        if user is not None:
            request.user = SimpleLazyObject(lambda: self._verify_user(request, user))

        return None

    def _verify_user(self, request, user):
        user.tfa_device = None

        if user.is_one_factor_authenticated:
            device_id = request.session.get(DEVICE_ID_SESSION_KEY)
            device = load_device(device_id) if device_id else None

            # Ignore the device that doesn't belong to the user.
            if (device is not None) and (device.user.id != user.id):
                device = None

            if (device is None) and (DEVICE_ID_SESSION_KEY in request.session):
                del request.session[DEVICE_ID_SESSION_KEY]

            user.tfa_device = device

        return user
