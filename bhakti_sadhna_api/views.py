from .models import *
from .serializer import *
from django.http import Http404, HttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAdminUser, AllowAny, IsAuthenticated
from .permissions import IsAdminOrReadOnly
from django.views import View
from .generate_custom_tokens import otp_token_for_registeration, otp_token_for_reset_password
import uuid, datetime
from .authentications import RegisterationOtpAuthentication, ForgetPasswordOtpAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from .renderer import UserRenderer


#******************** Generate Tokens Manually For Authentication *********************/

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

#******************** End of Generate Tokens Manually For Authentication *********************/


class AttendenceListView(generics.GenericAPIView):
    serializer_class = AttendenceSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def get(self, request):
        attendence = Attendence.objects.all().filter(user=request.user.id, date=datetime.date.today())
        serializer = self.serializer_class(attendence, many=True)
        serializer.data.append(f'email:{request.user.email}') 
        return Response(**serializer.data)
    

class TaskListView(generics.ListCreateAPIView):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    # authentication_classes = [BasicAuthentication]
    # permission_classes = [IsAdminOrReadOnly]

class Test(View):
    def get(self, request):
        return HttpResponse(request.user.is_authenticated)


class RegisterUserAPIView(generics.GenericAPIView):
    serializer_class = RegisterUserSerializer
    permission_classes = [AllowAny]
    renderer_classes = [UserRenderer]
    

    def post(self, request):
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception=True)
        email = request.POST['email']
        password = request.POST['password']
        otp = str(int(uuid.uuid1()))[:6]
        token = otp_token_for_registeration(email, password, otp)
        try:
            send_mail(
                'Register Account',
                'Otp for your registeration is ' + otp,
                'ankit971869@gmail.com',
                [email],
                fail_silently=False,
                )
        except exceptions as e:
            return Response({"errors":"e"})
        try:
            return Response({
                "token" : token
            })
        except:
            return Response(serializer.errors)

class ValidateOtpForRegisterationAPIView(generics.GenericAPIView):
    serializer_class = ValidateOtpForRegisterationSerializer
    permission_classes = [AllowAny]
    authentication_class = RegisterationOtpAuthentication
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp = serializer.data['otp']
        user = self.authentication_class.authenticate(self, request, otp)
        token = get_tokens_for_user(user)
        try:
            return Response({"msg":"registeration successful",
            "user" : user[0].email, 
            "refresh_token" : token['refresh'],
            "access_token" : token['access']
            })  
        except:
            return Response(serializer.errors)  


class LoginAPIView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer
    renderer_classes = [UserRenderer]

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        print(serializer)
        serializer.is_valid(raise_exception = True)
        username = serializer.data['email']
        password = serializer.data['password']
        user = authenticate(username=username, password=password)
        if user is None:
            return Response({
                "errors":"Invalid username or password"
            })
        token = get_tokens_for_user(user)
        try:
            return Response({
            "msg" : "login successful", 
            "refresh_token" : token['refresh'],
            "access_token" : token['access']
            })
        except:
            return Response(serializer.errors)    

class ChangePasswordAPIView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context = {'user':request.user})
        serializer.is_valid(raise_exception=True)
        try:
            return Response({"msg":"Password Changed Successfully."})
        except:
            return Response(serializer.errors)


class ForgetPasswordAPIView(generics.GenericAPIView):
    serializer_class = ForgetPasswordSerializer
    permission_classes = [AllowAny]
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data['email']
        try:
            user = User.objects.get(email=email)
        except:
            return Response({
                "errors":"User with this email id doesn't exist."
            })
        otp = str(int(uuid.uuid1()))[:6]
        token = otp_token_for_reset_password(email, otp)
        try:
            send_mail(
                'Register Account',
                'Otp for your registeration is ' + otp,
                'ankit971869@gmail.com',
                [email],
                fail_silently=False,
                )
        except exceptions as e:
            return Response({"error": e})
        try:
            return Response({
                "token" : token
            })
        except:
            return Response(serializer.errors)


class ValidateOtpForForgetPasswordAPIView(generics.GenericAPIView):
    serializer_class = ValidateOtpForForgetPasswordSerializer
    authentication_class = ForgetPasswordOtpAuthentication
    permission_classes = [AllowAny]
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp = serializer.data['otp']
        password = request.POST['password']
        user = self.authentication_class.authenticate(self, request, otp)
        user[0].set_password(password)
        user[0].save()
        token = get_tokens_for_user(user[0])
        try:
            return Response({"msg":"registeration successful",
            "user" : user[0].email, 
            "refresh_token" : token['refresh'],
            "access_token" : token['access']
            })    
        except:
            return Response(serializer.errors)