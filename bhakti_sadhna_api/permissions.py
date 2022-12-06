from rest_framework  import permissions
import jwt
from django.conf import settings
from django.contrib.auth.models import User

class IsAuthenticatedForPasswordReset(permissions.BasePermission):
    def has_permission(self, request, *args, **kwargs):
            authorization_heaader = request.headers.get('Authorization')
            if not authorization_heaader:
                return None
            try:
                # header = 'Token xxxxxxxxxxxxxxxxxxxxxxxx'
                access_token = authorization_heaader.split(' ')[1]
                payload = jwt.decode(
                    access_token, settings.SECRET_KEY, algorithms=['HS256'])

            except jwt.ExpiredSignatureError:
                raise exceptions.AuthenticationFailed('access_token expired')
            except IndexError:
                raise exceptions.AuthenticationFailed('Token prefix missing')

            user = User.objects.filter(email=payload['email_id']).first()
            print(user)
            if user is None:
                raise exceptions.AuthenticationFailed('User not found')

            if not user.is_active:
                raise exceptions.AuthenticationFailed('user is inactive')

            # self.enforce_csrf(request)
            return (user, None)



class IsAdminOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        print('this is running')
        print(request.user, request.method)
        if request.method in permissions.SAFE_METHODS:
            return True
        else:
            return request.user.is_staff


            
