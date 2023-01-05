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
from django.core.mail import send_mail
import os
from smtplib import SMTPException

#******************** Test View for testing purpose *********************/

class Test(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        return HttpResponse(request.user.is_authenticated)

#******************** End of Test View *********************/


#******************** Generate Tokens Manually For Authentication *********************/

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

#******************** End of Generate Tokens Manually For Authentication *********************/


#******************** User Registeration View *********************/

class RegisterUserAPIView(generics.GenericAPIView):
    serializer_class = RegisterUserSerializer
    permission_classes = [AllowAny]
    

    def post(self, request):
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data['email']
        password = serializer.data['password']
        first_name = serializer.data['first_name']
        last_name = serializer.data['last_name']
        otp = str(int(uuid.uuid1()))[:6]
        token = otp_token_for_registeration(email, password, first_name, last_name, otp)
        try:
            send_mail(
                'Register Account',
                'Otp for your registeration is ' + otp,
                os.environ.get('EMAIL_HOST_USER',''),
                [email],
                fail_silently=False,
                )
        except SMTPException as e:
            return Response({"status" : False, "msg" : str(e)})
        try:
            return Response({
                "status" : True,
                "msg" : "Otp sent successfully.",
                "data" : {
                    "token" : token
                }
            })
        except:
            return Response


#******************** End of Registeration View *********************/

#******************** Otp Validation View for User Registeration *********************/

class ValidateOtpForRegisterationAPIView(generics.GenericAPIView):
    serializer_class = ValidateOtpForRegisterationSerializer
    permission_classes = [AllowAny]
    authentication_class = RegisterationOtpAuthentication

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp = serializer.data['otp']

        user = self.authentication_class.authenticate(self, request, otp)

        token = get_tokens_for_user(user[0])
        try:
            return Response({
                "status" : True,
                "msg":"registeration successful",
                "data" : {
                    "user" : user[0].email, 
                    "refresh_token" : token['refresh'],
                    "access_token" : token['access']
                }
            })  
        except:
            return Response 

#******************** End of Otp Validation View *********************/

#******************** Login View *********************/

class LoginAPIView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer
    
    # renderer_classes = [UserRenderer]

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception = True)
        username = serializer.data['email']
        password = serializer.data['password']
        user = authenticate(username=username, password=password)
        if user is None:
            return Response({
                "status" : "False",
                "msg" : "Invalid username or password"
            })
        token = get_tokens_for_user(user)
    
        return Response({
            "status" : True,
            "msg" : "login successful", 
            "data" : {
                "user" : user.id,
                "refresh_token" : token['refresh'],
                "access_token" : token['access']
            }
        })
    

#******************** End of Login View *********************/


#******************** Password change view while logged in  *********************/

class ChangePasswordAPIView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context = {'user':request.user})
        serializer.is_valid(raise_exception=True)
        try:
            return Response({
                "status" : True,
                "msg" : "Password Changed Successfully."
                })
        except:
            return Response



#******************** End of password change View *********************/


#******************** End of password change View *********************/

class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            RefreshToken(serializer.data['refresh_token']).blacklist()
        except TokenError as e: 
            return Response({
                "status" : False,
                "msg" : "Refresh token is not valid. It should be sent in body with refresh tag"
            })
        return Response({
            "status" : True,
            "msg" : "Logout Successfully"})

#******************** End of Logout View *********************/

#******************** Forget Password View *********************/

class ForgetPasswordAPIView(generics.GenericAPIView):
    serializer_class = ForgetPasswordSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data['email']
        try:
            user = User.objects.get(email=email)
        except:
            return Response({
                "status" : False,
                "msg" : "User with this email id doesn't exist."
            })
        otp = str(int(uuid.uuid1()))[:6]
        token = otp_token_for_reset_password(email, otp)
        try:
            send_mail(
                'Register Account',
                'Otp for your registeration is ' + otp,
                os.environ.get('EMAIL_HOST_USER',''),
                [email],
                fail_silently=False,
                )
        except exceptions as e:
            return Response({
                "status" : False,
                "msg" : e
                })
        try:
            return Response({
                "status" : True,
                "msg" : "Otp Sent Successfully",
                "data" : {
                    "token" : token
                }
            })
        except:
            return Response


#******************** End of Forget Password View *********************/


#******************** Otp Validation View for forget Password *********************/

class ValidateOtpForForgetPasswordAPIView(generics.GenericAPIView):
    serializer_class = ValidateOtpForForgetPasswordSerializer
    authentication_class = ForgetPasswordOtpAuthentication
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp = serializer.data['otp']
        password = serializer.data['password']
        user = self.authentication_class.authenticate(self, request, otp)
        user[0].set_password(password)
        user[0].save()
        token = get_tokens_for_user(user[0])
        try:
            return Response({
                "status" : True,
                "msg":"registeration successful",
                "data" : {
                    "user" : user[0].email, 
                    "refresh_token" : token['refresh'],
                    "access_token" : token['access']
                }
            })    
        except:
            return Response

#******************** End of Forget Password View *********************/

#******************** Handling Attendence, punch in, punch out *********************/

class AttendenceListView(generics.GenericAPIView):
    serializer_class = AttendenceSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        attendence = Attendence.objects.all().filter(user=request.user.id, date=datetime.date.today())
        serializer = self.serializer_class(attendence, many=True)
        return Response({
            "status" : True, 
            "data" : {
                "date" : str(attendence[0].date),
                "punch in" : attendence[0].punch_in,
                "user" : attendence[0].user.email,
                "first_name" : attendence[0].user.first_name,
                "last_name" : attendence[0].user.last_name,
                "attendence status" : attendence[0].attendence_status
            }
            })

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            attendence = Attendence.objects.get(user=request.user.id, date=serializer.data['date'])
        except:
            return Response({
                "status" : False,
                "msg" : "No Detail Found"
            })

        if serializer.data['date'] == str(datetime.date.today()) and attendence.attendence_status == 'A' and serializer.data['punch_status'] == True:
            attendence.attendence_status = 'P'
            print(attendence.attendence_status)
            attendence.punch_in = datetime.datetime.now().strftime("%H:%M:%S")
            attendence.save()
            return Response({
                "status" : True, 
                "data" : {
                    "date" : str(attendence.date),
                    "punch in" : attendence.punch_in,
                    "user" : attendence.user.email,
                    "first_name" : attendence.user.first_name,
                    "last_name" : attendence.user.last_name,
                    "attendence status" : attendence.attendence_status
                }
            })
        

        if serializer.data['date'] == str(datetime.date.today()) and attendence.attendence_status == 'P' and serializer.data['punch_status'] == True:
            return Response({
                "status" : False, 
                "msg" : "Attendence Already Marked"
            })
        
        # if serializer.data['date'] == str(datetime.date.today()) and attendence.status == 'A' and serializer.data['punch_status'] == 'punch_in':
        #     attendence.status = 'N'
        #     attendence.punch_in = datetime.datetime.now().strftime("%H:%M:%S")
        #     attendence.save()
        #     return Response({
        #         "status" : True, 
        #         "data" : {
        #             "date" : str(attendence.date),
        #             "punch in" : attendence.punch_in,
        #             "punch out" : attendence.punch_out,
        #             "user" : attendence.user.email,
        #             "attendence status" : attendence.attendence_status
        #         }
        #     })

        # elif serializer.data['date'] == str(datetime.date.today()) and attendence.status == 'N' and serializer.data['punch_status'] == 'punch_out':
        #     attendence.status = "P"
        #     attendence.punch_out = datetime.datetime.now().strftime("%H:%M:%S")
        #     attendence.save()
        #     return Response({
        #         "status" : True, 
        #         "data" : {
        #             "date" : str(attendence.date),
        #             "punch in" : attendence.punch_in,
        #             "punch out" : attendence.punch_out,
        #             "user" : attendence.user.email,
        #             "attendence status" : attendence.attendence_status
        #         }
        #     })

        else :
            return Response({
                "status" : True, 
                "data" : {
                    "date" : str(attendence.date),
                    "punch in" : attendence.punch_in,
                    "user" : attendence.user.email,
                    "first_name" : attendence.user.first_name,
                    "last_name" : attendence.user.last_name,
                    "attendence status" : attendence.attendence_status
                }   
            })

    
#******************** End of Atttendenc View *********************/



#******************** Task View *********************/

class TaskListView(generics.ListCreateAPIView):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    # authentication_classes = [BasicAuthentication]
    # permission_classes = [IsAdminOrReadOnly]

    def get(self, request):
        data = Task.objects.all()
        return Response({
            "status" : True,
            "data" : list(self.queryset.values())
        })

#******************** End of Task View *********************/
