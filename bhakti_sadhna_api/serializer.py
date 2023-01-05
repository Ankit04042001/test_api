from . models import *
from rest_framework import serializers
from rest_framework import generics
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import TokenError, RefreshToken


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


# ************ User Registration serializer ***************************************************#

class RegisterUserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'})
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'password', 'password2')
        # extra_kwargs = {'password': {'write_only': True},'password2': {'write_only': True} }

    def validate(self, attrs):
        if attrs.get('first_name') is None:
            raise serializers.ValidationError("First Name is required")
        if attrs.get('last_name') is None:
            raise serializers.ValidationError("Last Name is required")
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password Doesn't match.")
        return attrs


################ otp validation for user registeration #####################

class ValidateOtpForRegisterationSerializer(serializers.ModelSerializer):
    otp = serializers.CharField(max_length = 6)
    class Meta:
        model = User
        fields = ('otp',)

#******************************* Login Serializer ****************************#

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    
    class Meta:
        model = User
        fields = ('email','password')
    
#***************************** Change Password Serializer ***************************#

class ChangePasswordSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ('password', 'password2')
        extra_kwargs = {'password': {'write_only': True},'password2': {'write_only': True} }

    def validate(self, attrs):
        user = self.context.get('user')
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password Doesn't match.")
        user.set_password(password)
        user.save()
        return attrs


#******************************* Logout Serializer ********************************#


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh_token']
        return attrs


#******************************* End of Logout Serializer ********************************#

#******************************* Forget Password Serializer ********************************#
class ForgetPasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ('email',)

################ otp validation for user reset password #####################

class ValidateOtpForForgetPasswordSerializer(serializers.ModelSerializer):
    otp = serializers.CharField(max_length = 6)
    password2 = serializers.CharField(style={'input_type':'password'})
    class Meta:
        model = User
        fields = ('otp','password', 'password2')
        # extra_kwargs = {'password': {'write_only': True},'password2': {'write_only': True} }

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password Doesn't match.")
        return attrs



class AttendenceSerializer(serializers.ModelSerializer):
    punch_status = serializers.BooleanField(allow_null=True)
    class Meta:
        model = Attendence
        fields = '__all__'        

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = '__all__'

