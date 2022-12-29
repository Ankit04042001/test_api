import datetime
import jwt
from django.conf import settings


# def generate_access_token(user):

#     access_token_payload = {
#         'user_id': user.id,
#         'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=5),
#         'iat': datetime.datetime.utcnow(),
#     }
#     access_token = jwt.encode(access_token_payload,
#                               settings.SECRET_KEY, algorithm='HS256')
#     return access_token


def otp_token_for_registeration(email, password, first_name, last_name, otp):
    registeration_token_payload = {
        'otp' : otp,
        'email': email,
        'password' : password,
        'first_name' : first_name,
        'last_name' : last_name,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
        'iat': datetime.datetime.utcnow()
    }
    registeration_token = jwt.encode(
        registeration_token_payload, settings.SECRET_KEY, algorithm='HS256')

    return registeration_token


def otp_token_for_reset_password(email, otp):
    reset_token_payload = {
        'otp' : otp,
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
        'iat': datetime.datetime.utcnow()
    }
    reset_token = jwt.encode(
        reset_token_payload, settings.SECRET_KEY, algorithm='HS256')

    return reset_token
