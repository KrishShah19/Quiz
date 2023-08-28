from django.shortcuts import render
from django import views
from django.views import View
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializer import *
from .emails import *
from quiz import serializer
from django.contrib.auth import authenticate, login
from django.contrib.auth import login
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib.auth.views import PasswordResetView
from django.contrib import messages
from .serializer import UserSerializer
from .emails import send_otp
# Create your views here.
class RegisterAPI(APIView):
    def post(self, request):
        try:
            data = request.data
            serializer = UserSerializer(data=data)
            if serializer.is_valid():
                print("Serializer is valid")
                user = serializer.save()
                print("User instance created:", user)
                send_otp(user.email)
                return Response({
                    'status': 200,
                    'message': 'Registered successfully. Check email for OTP verification.',
                    'data': serializer.data
                })
            else:
                print("Serializer errors:", serializer.errors)
                return Response({
                    'status': 400,
                    'message': 'Something went wrong with data validation.',
                    'data': serializer.errors
                })
        except Exception as e:
            print(e)
            return Response({
               'status': 400,
               'message': 'Something went wrong.',
               'data': e
            })

    

class VerifyOTP(APIView):
    def post(self, request):
        try:
            data = request.data
            serializer = VerifyAccount(data=data)
            if serializer.is_valid():
                email = serializer.data['email']
                otp = serializer.data['otp']

                user = User.objects.filter(email=email).first()  # Use .first()
                if user is None:
                    return Response({
                        'status': 400,
                        'message': 'Invalid email.',
                        'data': 'invalid_email'
                    })
                if user.otp != otp:
                    return Response({
                        'status': 400,
                        'message': 'Invalid OTP.',
                        'data': 'invalid_otp'
                    })

                user.is_verified = True
                user.save()  # Now saving the user object
                return Response({
                    'status': 200,
                    'message': 'Account is verified.',
                    'data': {}
                })
            return Response({
                'status': 400,
                'message': 'Something went wrong.',
                'data': serializer.errors
            })
        except Exception as e:
            print(e)

User = get_user_model()

class LoginAPI(APIView):
    def post(self, request):
        try:
            data = request.data
            username = data.get('username')
            password = data.get('password')

            user = authenticate(username=username, password=password)

            if user is not None:
                login(request, user)  # Log the user in
                return Response({
                    'status': 200,
                    'message': 'Login successful.',
                    'data': {}
                })
            else:
                return Response({
                    'status': 400,
                    'message': 'Invalid credentials.',
                    'data': {}
                })
        except Exception as e:
            print(e)


class LoginView(View):
    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('index')  # Redirect to your desired page
        else:
            return render(request,'login.html', {'error': 'Invalid credentials'})

class IndexView(View):
    def get(self, request):
        if request.user.is_authenticated:
            return render(request, 'index.html', {'username': request.user.username})
        else:
            return redirect('login')
        
class ForgotView(PasswordResetView):
    def get(self, request):
        return render(request, 'forgot.html')
    
    # this view should send otp to the entered email
    def post(self, request):
        data = request.POST
        email = data.get('email')
        if send_otp(email):
            print("OTP SENT")
            messages.success = 'OTP has been sent to your email.'
            return render(request, self.template_name, {'success_message': messages.success})

            # return redirect('verify_otp')  # Redirect to OTP verification page
        else:
            messages.error = 'Failed to send OTP. Please try again later.'
            return render(request, 'forgot.html', {'error_message': messages.error})
        
class VerifyOTPView(View):
    template_name = 'registration/verify_otp.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        data = request.POST
        email = data.get('email')
        otp = data.get('otp')
        print()

        user = User.objects.filter(email=email, otp=otp).first()
        if user:
            user.is_verified = True
            user.save()
            messages.success(request, 'OTP verified successfully!')
            return redirect('index')
        else:
            messages.error(request, 'Incorrect OTP. Please try again.')
            return render(request, self.template_name)  
        
from django.shortcuts import render
from django.views import View

class RegisterView(View):
    template_name = 'registration/register.html'

    def get(self, request):
        return render(request, self.template_name)

        
# from django.shortcuts import render, redirect
# from django.views import View
# from django.contrib import messages
# from django.contrib.auth import get_user_model
# from .emails import send_otp

# User = get_user_model()

# class RegisterView(View):
#     template_name = 'registration/register.html'

#     def get(self, request):
#         return render(request, self.template_name)

#     def post(self, request):
#         data = request.POST
#         username = data.get('username')
#         email = data.get('email')
#         password = data.get('password')
        
#         user = User.objects.create_user(username=username, email=email, password=password)
        
#         if send_otp(email):
#             request.session['registered_user_email'] = email
#             return redirect('verify_otp')
#         else:
#             messages.error(request, 'Failed to send OTP. Please try again.')
#             return render(request, self.template_name)

class PythonQuiz(View):
    def get(self, request):
        return render(request, 'python_quiz.html')

class DjangoQuiz(View):
    def get(self, request):
        return render(request, 'django_quiz.html')

class JavaQuiz(View):
    def get(self, request):
        return render(request, 'java_quiz.html')
