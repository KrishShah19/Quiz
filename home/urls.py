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
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', LoginView.as_view(), name='login'),
    path('index/', login_required(IndexView.as_view()), name='index'),
    path('register/', RegisterView.as_view(), name='register'),
    # path('forgot/', ForgotView.as_view(), name='forgot'),
    # path('verify_otp/<str:email>/', VerifyOTPView.as_view(), name='verify_otp'),
    path('verify_otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('logout/', LogoutView.as_view(), name='logout'),
    # path('api/register/',RegisterAPI.as_view(), name='registerapi'),
    path('python_quiz/', PythonQuiz.as_view(), name='python_quiz'),
    path('django_quiz/', DjangoQuizView.as_view(), name='django_quiz'),
    path('javascript_quiz/', JavaScriptQuiz.as_view(), name='javascript_quiz'),

    path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    path('email_sent/', EmailSentView.as_view(), name='email_sent'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('javascript_quiz/result/', JavaScriptResultView.as_view(), name='javascript_result'),
    path('django_quiz/result/', DjangoResultView.as_view(), name='django_result'),
    path('python_quiz/result/', PythonResultView.as_view(), name='python_result'),
    # path('user/questions/', UserQuestionView.as_view(), name='user_questions'),
    # path('admin/questions/', AdminQuestionView.as_view(), name='admin_questions'),  
    # path('email_register/', email_register, name='email_register'),  # Process registration and send email
    path('api/send_email/', RegisterAPI.as_view(), name='send_emails'),

    path('set_password/<str:uidb64>/<str:token>/', SetPasswordView.as_view(), name='set_password'),
    path('password_reset_invalid/', PasswordResetInvalid.as_view(), name='password_reset_invalid'),
    path('send_email/', SendEmailView.as_view(), name='send_email'),
    path('add_quiz/', AddQuizView.as_view(), name='add_quiz'),
    # path('quiz/<str:category>/', QuizView.as_view(), name='quiz_view'),


]
