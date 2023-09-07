from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
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
    def get(self, request):
        return render(request, 'login.html')
    def post(self, request):
        try:
            # user_username = request.user.username
            # request.session['_auth_user_username'] = user_username

            data = request.data
            username = data.get('username')
            password = data.get('password')

            user = authenticate(username=username, password=password)
            # logger.debug('Debugging message to trace the flow of execution')

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


from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator

class IndexView(View):
    @method_decorator(login_required)
    def get(self, request):
        if request.user.is_authenticated:
            return render(request, 'index.html', {'username': request.user.username})
        else:
            return redirect('/')
        
from django.urls import reverse  # Import reverse

class ForgotView(PasswordResetView):
    def get(self, request):
        return render(request, 'forgot.html')
    
    def post(self, request):
        data = request.POST
        email = data.get('email')
        if send_otp(email):
            messages.success(request, 'OTP has been sent to your email.')
            verify_otp_url = reverse('verify_otp', args=[email])
            return HttpResponseRedirect(verify_otp_url)
        else:
            messages.error(request, 'Failed to send OTP. Please try again later.')
            return render(request, 'forgot.html', {'error_message': messages.error})

class VerifyOTPView(PasswordResetView):
    template_name = 'registration/verify_otp.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        data = request.POST
        email = data.get('email')
        otp = data.get('otp')

        user = User.objects.filter(email=email, otp=otp).first()
        if user:
            user.is_verified = True
            user.save()
            messages.success(request, 'OTP verified successfully!')
            return redirect('index')
        else:
            messages.error(request, 'Incorrect OTP. Please try again.')
            return render(request, self.template_name)

# class ForgotView(PasswordResetView):
#     def get(self, request):
#         return render(request, 'forgot.html')
    
#     # this view should send otp to the entered email
#     def post(self, request):
#         print("POST CALLED")
#         data = request.POST
#         email = data.get('email')
#         if send_otp(email):
#             print("OTP SENT")
#             messages.success(request, 'OTP has been sent to your email.')
#             verify_otp_url = reverse('verify_otp', args=[email])
#             return HttpResponseRedirect(verify_otp_url)
#             # return redirect(verify_otp_url)
#             # return redirect('verify_otp')  # Redirect to OTP verification page
#         else:
#             messages.error(request, 'Failed to send OTP. Please try again later.')
#             return render(request, 'forgot.html', {'error_message': messages.error})
        
# # from django.views.decorators.csrf import csrf_protect
# # @csrf_protect
# class VerifyOTPView(PasswordResetView):
#     template_name = 'registration/verify_otp.html'

#     def get(self, request):
#         return render(request, self.template_name)

#     def post(self, request):
#         data = request.POST
#         email = data.get('email')
#         otp = data.get('otp')
#         print()

#         user = User.objects.filter(email=email, otp=otp).first()
#         if user:
#             user.is_verified = True
#             user.save()
#             messages.success(request, 'OTP verified successfully!')
#             return redirect('index')
#         else:
#             messages.error(request, 'Incorrect OTP. Please try again.')
#             return render(request, self.template_name)  
        
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
from .models import *
from django.contrib.sessions.models import Session
from uuid import UUID

class PythonQuiz(View):
    @method_decorator(login_required)
    def get(self, request):
        python_category = Category.objects.get(category_name='Python')
        # questions = Question.objects.filter(category=python_category)
        # answers = Answer.objects.filter(question__in=questions)

        questions = list(Question.objects.filter(category=python_category))
        answers = list(Answer.objects.all())    
        

        random.shuffle(questions)
        random.shuffle(answers)
         # Create a session key for this user's quiz progress
        session_key = f'quiz_progress_{request.user.id}'
        # Convert UUIDs to strings before storing them in the session
        questions_ids = [str(question.uuid) for question in questions]
        answers_ids = [str(answer.uuid) for answer in answers]
        request.session[session_key] = {
            'questions': questions_ids,
            'answers': answers_ids,
            'total_questions': len(questions),
        }

        print("Session Keys:", request.session.keys())
        print("User ID from Session:", request.session.get(f'quiz_progress_{request.user.id}'))
        context = {
            'questions': questions,
            'answers': answers,
            'total_questions': len(questions),
        }
        return render(request, 'python_quiz.html', context)
    
    def post(self, request):
        # Get the session key for this user's quiz progress
        session_key = f'quiz_progress_{request.user.id}'
        quiz_progress = request.session.get(session_key)

        if not quiz_progress:
            # Session has expired or the user is trying to submit without starting the quiz
            return HttpResponseRedirect('/index/')  # Redirect to some appropriate page
        
        # Convert the stored UUID strings back to UUID objects
        questions_ids = [UUID(question_id) for question_id in quiz_progress['questions']]
        answers_ids = [UUID(answer_id) for answer_id in quiz_progress['answers']]
        
        # You can access the quiz progress data as quiz_progress['questions'] and quiz_progress['answers']
        
        # Handle the submitted answers here
        
        # Clear the quiz progress from the session
        del request.session[session_key]

        return HttpResponseRedirect('/index/')


# class PythonQuiz(View):
#     def get(self, request):
#         return render(request, 'python_quiz.html')
    
    # def get_quiz(request):
    #     try:
    #         question_objs=list(Question.objects.all())
    #         data=[]
    #         random.shuffle(question_objs)
    #         for question_obj in question_objs:
    #             data.append({
    #                 "category":question_obj.category.category_name,
    #                 "question":question_obj.question,
    #                 "marks":question_obj.marks,
    #                 "answer":question_obj.get_answers()
    #             })
    #         payload={'status':True, 'data':data}
    #         return JsonResponse(payload)
    #     except Exception as e:
    #         print(e)
    #     return HttpResponse("Something went wrong")
            

class DjangoQuiz(View):
    def get(self, request):
        return render(request, 'django_quiz.html')

from .models import Category, Question, Answer  # Import your models here
class JavaQuiz(View):
    def get(self, request):
        java_category = Category.objects.get(category_name='JS')
        # questions = Question.objects.filter(category=java_category)
        # answers = Answer.objects.filter(question__in=questions)
        questions = list(Question.objects.filter(category=java_category))
        answers = list(Answer.objects.all())    

        random.shuffle(questions)
        random.shuffle(answers)
        context = {
            'questions': questions,
            'answers': answers,
            'total_questions': len(questions),
        }
        return render(request, 'java_quiz.html', context)

from django.contrib.auth import logout
class LogoutView(View):
    def get(self, request):
        logout(request)
        return redirect('/')
    
# class UserAnswer(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     question = models.ForeignKey(Question, on_delete=models.CASCADE)
#     selected_answer = models.ForeignKey(Answer, on_delete=models.CASCADE)
#     is_correct = models.BooleanField(default=False)

#     def __str__(self):
#         return f"{self.user.username} - {self.question.question}"
