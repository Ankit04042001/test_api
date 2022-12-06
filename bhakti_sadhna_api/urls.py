from django.urls import path
from .views import AttendenceListView, TaskListView, Test, RegisterUserAPIView, ValidateOtpForRegisterationAPIView, LoginAPIView, ChangePasswordAPIView, ForgetPasswordAPIView, ValidateOtpForForgetPasswordAPIView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from rest_framework_simplejwt.views import TokenVerifyView



urlpatterns = [
    path('attendence/', AttendenceListView.as_view(), name='attendence'),
    path('task/', TaskListView.as_view(), name='task'),
    # path('login/', Login.as_view(), name='login'),
    path('test/', Test.as_view(), name='test'),
    path('register/', RegisterUserAPIView.as_view(), name='register'),
    path('validate_otp_for_registeration/', ValidateOtpForRegisterationAPIView.as_view(), name='validate_otp_for_registeration'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('change_password/', ChangePasswordAPIView.as_view(), name='change_password'),
    path('forget_password/', ForgetPasswordAPIView.as_view(), name='forget_password'),
    path('validate_otp_for_forget_password/', ValidateOtpForForgetPasswordAPIView.as_view(), name='validate_otp_for_forget_password'),
    

]