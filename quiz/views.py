import logging
from .models import *
import random
from django.shortcuts import render, HttpResponseRedirect, redirect, reverse
from django.contrib.auth import logout
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from django.views import View
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializer import *
from .emails import *
from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
from django.contrib.auth.views import PasswordResetView
from django.contrib import messages
from .serializer import UserSerializer
from .emails import send_otp
from django.contrib.auth.hashers import make_password  # Import make_password
from rest_framework import status
from .serializer import UserSerializer, VerifyAccount
from django.db.models import F

class RegisterAPI(APIView):
    """
    RegisterAPI: Handles user registration via API.

    - POST: Register a new user.
    """
    def post(self, request):
        try:
            data = request.data
            email = data.get('email')
            existing_user = User.objects.filter(email=email).first()
            if existing_user:
                return Response({
                    'status': status.HTTP_409_CONFLICT,
                    'message': 'Email already exists. Please use a different email address.',
                    'data': {'email_exists': True}
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer = UserSerializer(data=data)
            if serializer.is_valid():
                user = serializer.save()
                password = make_password(data['password'])
                user = serializer.save(password=password)
                send_otp(user.email)
                return Response({
                    'status': 200,
                    'message': 'Registered successfully. Check email for OTP verification.',
                    'data': serializer.data
                })
            else:
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
    """
    VerifyOTP: Handles OTP verification via API.

    - POST: Verify the OTP for a user's account.
    """
    def post(self, request):
        try:
            data = request.data
            serializer = VerifyAccount(data=data)
            if serializer.is_valid():
                email = serializer.data['email']
                otp = serializer.data['otp']

                user = User.objects.filter(email=email).first()
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
                user.save()
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
    """
    LoginAPI: Handles user login via API.

    - POST: Log in a user.
    """
    def post(self, request):
        try:
            data = request.data
            username = data.get('username')
            password = data.get('password')

            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
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
    """
    LoginView: Handles user login via web interface.
    """
    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('index')
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})

class IndexView(View):
    """
    IndexView: Handles the main index page.
    """
    @method_decorator(login_required)
    def get(self, request):
        if request.user.is_authenticated:
            return render(request, 'index.html', {'username': request.user.username})
        else:
            return redirect('/')

logger = logging.getLogger(__name__)

class ForgotView(PasswordResetView):
    """
    ForgotView: Handles password reset via web interface.
    """
    def get(self, request):
        return render(request, 'forgot.html')

    def post(self, request):
        data = request.POST
        email = data.get('email')
        if send_otp(email):
            messages.success(request, 'OTP has been sent to your email.')
            verify_otp_url = reverse('verify_otp', args=[email])
            logger.info(f"OTP sent to {email}")
            return HttpResponseRedirect(verify_otp_url)
        else:
            messages.error(
                request, 'Failed to send OTP. Please try again later.')
            return render(request, 'forgot.html', {'error_message': 'Failed to send OTP. Please try again later.'})

class VerifyOTPView(PasswordResetView):
    """
    VerifyOTPView: Handles OTP verification via web interface.
    """
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

class RegisterView(View):
    """
    RegisterView: Handles user registration via web interface.
    """
    template_name = 'registration/register.html'

    def get(self, request):
        email = request.GET.get('email')
        email_already_exists = User.objects.filter(email=email).exists()

        return render(request, self.template_name, {'email_exists': email_already_exists})

class PythonQuiz(View):
    """
    PythonQuiz: Handles the Python quiz page.
    """
    def get(self, request):
        python_category = Category.objects.get(category_name='Python')
        questions = list(Question.objects.filter(category=python_category))
        answers = list(Answer.objects.all())

        random.shuffle(questions)
        random.shuffle(answers)

        total_fib_questions = len(
            [q for q in questions if q.question_type == 'FIB'])
        start_quiz = not request.session.get('quiz_started', False)

        if start_quiz:
            request.session['quiz_start_time'] = timezone.now().strftime(
                '%Y-%m-%d %H:%M:%S')
            request.session['quiz_started'] = True

        completed_quizzes = User.objects.get(username=request.user.username).completed_quizzes

        total_categories = Category.objects.count()
        if total_categories > 0:
            progress_percentage = (completed_quizzes / total_categories) * 100.0
        else:
            progress_percentage = 0.0

        context = {
            'questions': questions,
            'answers': answers,
            'total_questions': len(questions),
            'total_fib_questions': total_fib_questions,
            'start_quiz': start_quiz,
            'progress_percentage': progress_percentage,
        }
        return render(request, 'python_quiz.html', context)

    def post(self, request):
        python_category = Category.objects.get(category_name='Python')
        questions = list(Question.objects.filter(category=python_category))
        answers = list(Answer.objects.all())

        user_answers = []
        user_score = 0
        total_fib_questions = 0
        total_attempted = 0
        total_score = 0
        total_categories = 3

        for question in questions:
            selected_answer_uuid = request.POST.get(
                f'question_{question.uuid}')
            user_input = request.POST.get(f'question_{question.uuid}_input')
            correct_answer = None

            try:
                correct_answer = Answer.objects.get(
                    question=question, is_correct=True)
            except ObjectDoesNotExist:
                pass

            if question.question_type == 'FIB':
                user_answer_text = user_input if user_input else ""
                is_correct = user_input.strip().lower(
                ) == correct_answer.answer.strip().lower() if user_input else False
                if is_correct:
                    total_score += question.score
                    total_fib_questions += 1
                if user_input:
                    total_attempted += 1
            else:
                try:
                    selected_answer = Answer.objects.get(
                        uuid=selected_answer_uuid)
                    user_answer_text = selected_answer.answer if selected_answer else ""
                    is_correct = selected_answer_uuid == str(
                        correct_answer.uuid) if selected_answer else False
                    if is_correct:
                        total_score += question.score
                    if selected_answer_uuid:
                        total_attempted += 1
                except ObjectDoesNotExist:
                    selected_answer = None
                    user_answer_text = ""
                    is_correct = False

            user_answer = {
                'question_text': question.question,
                'user_answer': user_answer_text,
                'correct_answer': correct_answer.answer if correct_answer else 'N/A',
                'is_correct': is_correct,
            }

            user_answers.append(user_answer)

            user_answer_obj = UserAnswer.objects.create(
                user=request.user,
                question=question,
                selected_answer=selected_answer,
                is_correct=is_correct,
            )

        max_possible_score = sum([question.score for question in questions])
        if max_possible_score > 0:
            percentage = (total_score / max_possible_score) * 100
        else:
            percentage = 0

        completed_quizzes = User.objects.get(username=request.user.username).completed_quizzes
        total_quizzes = total_categories
        if completed_quizzes < total_quizzes:
            User.objects.filter(username=request.user.username).update(completed_quizzes=F('completed_quizzes') + 1)
        if total_categories > 0:
            progress_percentage = (completed_quizzes / total_categories) * 100.0
        else:
            progress_percentage = 0.0

        request.session['quiz_progress_percentage'] = progress_percentage
        request.session['python_quiz_user_answers'] = user_answers
        request.session['python_quiz_score'] = f"{total_score}/{max_possible_score}"
        request.session['python_quiz_percentage'] = round(percentage, 2)
        request.session['python_quiz_total_fib_questions'] = total_fib_questions

        return HttpResponseRedirect(reverse('python_result'))

class PythonResultView(View):
    """
    PythonResultView: Handles the Python quiz result page.
    """
    def get(self, request):
        score = request.session.get('python_quiz_score', '0/0')
        user_answers = request.session.get('python_quiz_user_answers', [])
        total_questions_attempted = len(user_answers)
        percentage = request.session.get('python_quiz_percentage', 0)

        context = {
            'score': score,
            'percentage': percentage,
            'user_answers': user_answers,
            'total_questions_attempted': total_questions_attempted,
        }

        return render(request, 'python_result.html', context)

class DjangoQuizView(View):
    """
    DjangoQuizView: Handles the Django quiz page.
    """
    def get(self, request):
        django_category = Category.objects.get(category_name='Django')
        questions = list(Question.objects.filter(category=django_category))
        answers = list(Answer.objects.all())

        random.shuffle(questions)
        random.shuffle(answers)

        total_fib_questions = len(
            [q for q in questions if q.question_type == 'FIB'])
        completed_quizzes = User.objects.get(username=request.user.username).completed_quizzes

        total_categories = Category.objects.count()
        if total_categories > 0:
            progress_percentage = (completed_quizzes / total_categories) * 100.0
        else:
            progress_percentage = 0.0

        context = {
            'questions': questions,
            'answers': answers,
            'total_questions': len(questions),
            'total_fib_questions': total_fib_questions,
            'progress_percentage': progress_percentage,
        }
        return render(request, 'django_quiz.html', context)

    def post(self, request):
        django_category = Category.objects.get(category_name='Django')
        questions = list(Question.objects.filter(category=django_category))
        answers = list(Answer.objects.all())

        user_answers = []
        user_score = 0
        total_fib_questions = 0
        total_attempted = 0
        total_score = 0
        total_categories = 3

        for question in questions:
            selected_answer_uuid = request.POST.get(
                f'question_{question.uuid}')
            user_input = request.POST.get(f'question_{question.uuid}_input')
            correct_answer = None

            try:
                correct_answer = Answer.objects.get(
                    question=question, is_correct=True)
            except ObjectDoesNotExist:
                pass

            if question.question_type == 'FIB':
                user_answer_text = user_input if user_input else ""
                is_correct = user_input.strip().lower(
                ) == correct_answer.answer.strip().lower() if user_input else False
                if is_correct:
                    total_score += question.score
                    total_fib_questions += 1
                if user_input:
                    total_attempted += 1
            else:
                try:
                    selected_answer = Answer.objects.get(
                        uuid=selected_answer_uuid)
                    user_answer_text = selected_answer.answer if selected_answer else ""
                    is_correct = selected_answer_uuid == str(
                        correct_answer.uuid) if selected_answer else False
                    if is_correct:
                        total_score += question.score
                    if selected_answer_uuid:
                        total_attempted += 1
                except ObjectDoesNotExist:
                    selected_answer = None
                    user_answer_text = ""
                    is_correct = False

            user_answer = {
                'question_text': question.question,
                'user_answer': user_answer_text,
                'correct_answer': correct_answer.answer if correct_answer else 'N/A',
                'is_correct': is_correct,
            }

            user_answers.append(user_answer)

            user_answer_obj = UserAnswer.objects.create(
                user=request.user,
                question=question,
                selected_answer=selected_answer,
                is_correct=is_correct,
            )

        max_possible_score = sum([question.score for question in questions])
        if max_possible_score > 0:
            percentage = (total_score / max_possible_score) * 100
        else:
            percentage = 0

        completed_quizzes = User.objects.get(username=request.user.username).completed_quizzes
        total_quizzes = total_categories
        if completed_quizzes < total_quizzes:
            User.objects.filter(username=request.user.username).update(completed_quizzes=F('completed_quizzes') + 1)
        if total_categories > 0:
            progress_percentage = (completed_quizzes / total_categories) * 100.0
        else:
            progress_percentage = 0.0

        request.session['quiz_progress_percentage'] = progress_percentage
        request.session['django_quiz_user_answers'] = user_answers
        request.session['django_quiz_score'] = f"{total_score}/{max_possible_score}"
        request.session['django_quiz_percentage'] = round(percentage, 2)
        request.session['django_quiz_total_fib_questions'] = total_fib_questions

        return HttpResponseRedirect(reverse('django_result'))

class DjangoResultView(View):
    """
    DjangoResultView: Handles the Django quiz result page.
    """
    def get(self, request):
        score = request.session.get('django_quiz_score', '0/0')
        user_answers = request.session.get('django_quiz_user_answers', [])
        total_questions_attempted = len(user_answers)
        percentage = request.session.get('django_quiz_percentage', 0)

        context = {
            'score': score,
            'percentage': percentage,
            'user_answers': user_answers,
            'total_questions_attempted': total_questions_attempted,
        }

        return render(request, 'django_result.html', context)

class JavaQuiz(View):
    """
    JavaQuiz: Handles the Java quiz page.
    """
    def get(self, request):
        java_category = Category.objects.get(category_name='JS')
        questions = list(Question.objects.filter(category=java_category))
        answers = list(Answer.objects.all())
        total_fib_questions = len([q for q in questions if q.question_type == 'FIB'])

        random.shuffle(questions)
        random.shuffle(answers)
        completed_quizzes = User.objects.get(username=request.user.username).completed_quizzes

        total_categories = Category.objects.count()
        if total_categories > 0:
            progress_percentage = (completed_quizzes / total_categories) * 100.0
        else:
            progress_percentage = 0.0

        context = {
            'questions': questions,
            'answers': answers,
            'total_questions': len(questions),
            'total_fib_questions': total_fib_questions,
            'progress_percentage': progress_percentage,
        }
        return render(request, 'java_quiz.html', context)

    def post(self, request):
        java_category = Category.objects.get(category_name='JS')
        questions = list(Question.objects.filter(category=java_category))
        answers = list(Answer.objects.all())

        user_answers = []
        user_score = 0
        total_score=0
        total_categories = 3

        for question in questions:
            selected_answer_uuid = request.POST.get(
                f'question_{question.uuid}')
            user_input = request.POST.get(f'question_{question.uuid}_input')
            correct_answer = Answer.objects.get(
                question=question, is_correct=True)

            if question.question_type == 'FIB':
                print(f'User input for question {question.uuid}: {user_input}')
                user_answer_text = user_input if user_input else ""
                is_correct = user_input.strip().lower(
                ) == correct_answer.answer.strip().lower() if user_input else False
                if is_correct:
                    user_score += question.score
            else:
                selected_answer = Answer.objects.get(uuid=selected_answer_uuid)
                user_answer_text = selected_answer.answer if selected_answer else ""
                is_correct = selected_answer_uuid == str(
                    correct_answer.uuid) if selected_answer else False
                if is_correct:
                    user_score += question.score

            user_answer = {
                'question_text': question.question,
                'user_answer': user_answer_text,  # Use 'user_answer' instead of 'user_response'
                'correct_answer': correct_answer.answer,
                'is_correct': is_correct,
            }

            user_answers.append(user_answer)

            user_answer_obj = UserAnswer.objects.create(
                user=request.user,
                question=question,
                selected_answer=Answer.objects.get(
                    uuid=selected_answer_uuid) if selected_answer_uuid else None,
                is_correct=is_correct,
            )

        total_attempted = len(questions)

        max_possible_score = sum([question.score for question in questions])
        if max_possible_score > 0:
            percentage = (user_score / max_possible_score) * 100
        else:
            percentage = 0

        completed_quizzes = User.objects.get(username=request.user.username).completed_quizzes
        total_quizzes = total_categories
        if completed_quizzes < total_quizzes:
            User.objects.filter(username=request.user.username).update(completed_quizzes=F('completed_quizzes') + 1)
        if total_categories > 0:
            progress_percentage = (completed_quizzes / total_categories) * 100.0
        else:
            progress_percentage = 0.0
        print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", progress_percentage,"^^^^^^^^^^^^^^^^^^^^^^^^^")

        request.session['quiz_progress_percentage'] = progress_percentage
        request.session['java_quiz_user_answers'] = user_answers
        request.session['java_quiz_score'] = f"{user_score}/{total_attempted}"
        request.session['java_quiz_percentage'] = round(percentage, 2)

        return HttpResponseRedirect(reverse('java_result'))

class JavaResultView(View):
    """
    JavaResultView: Handles the Java quiz result page.
    """
    def get(self, request):
        score = request.session.get('java_quiz_score', '0/0')
        user_answers = request.session.get('java_quiz_user_answers', [])
        total_questions_attempted = len(user_answers)
        percentage = request.session.get('java_quiz_percentage', 0)

        context = {
            'score': score,
            'percentage': percentage,
            'user_answers': user_answers,
            'total_questions_attempted': total_questions_attempted,
        }

        return render(request, 'java_result.html', context)

class LogoutView(View):
    """
    LogoutView: Handles user logout.
    """
    def get(self, request):
        logout(request)
        return redirect('/')
