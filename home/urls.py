"""
URL configuration for home project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from quiz.views import *
from django.contrib.auth.decorators import login_required


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', LoginView.as_view(), name='login'),
    path('index/', login_required(IndexView.as_view()), name='index'),
    path('register/', RegisterView.as_view(), name='register'),
    path('forgot/', ForgotView.as_view(), name='forgot'),
    path('api/verify_otp/', VerifyOTP.as_view(), name='verify_otpapi'),
    path('verify_otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('api/register/',RegisterAPI.as_view(), name='registerapi'),
    path('python_quiz/', PythonQuiz.as_view(), name='python_quiz'),
    path('django_quiz/', DjangoQuiz.as_view(), name='django_quiz'),
    path('java_quiz/', JavaQuiz.as_view(), name='java_quiz'),

]
