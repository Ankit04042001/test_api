from django.urls import path
from .views import (
    AttendenceListView, 
    TaskListView, 
    Test, 
    RegisterUserAPIView, 
    ValidateOtpForRegisterationAPIView, 
    LoginAPIView, 
    ChangePasswordAPIView, 
    LogoutAPIView,
    ForgetPasswordAPIView, 
    ValidateOtpForForgetPasswordAPIView
)

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from rest_framework_simplejwt.views import TokenVerifyView, TokenBlacklistView, TokenObtainPairView



urlpatterns = [
    path('attendence/', AttendenceListView.as_view(), name='attendence'),
    path('task/', TaskListView.as_view(), name='task'),
    path('test/', Test.as_view(), name='test'),
    path('register/', RegisterUserAPIView.as_view(), name='register'),
    path('validate_otp_for_registeration/', ValidateOtpForRegisterationAPIView.as_view(), name='validate_otp_for_registeration'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('change_password/', ChangePasswordAPIView.as_view(), name='change_password'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('forget_password/', ForgetPasswordAPIView.as_view(), name='forget_password'),
    path('validate_otp_for_forget_password/', ValidateOtpForForgetPasswordAPIView.as_view(), name='validate_otp_for_forget_password'),

]