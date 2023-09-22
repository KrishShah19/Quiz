import logging
from .models import *
import random
from django.shortcuts import render, HttpResponseRedirect, redirect, reverse
from django.contrib.auth import logout
from django.contrib.sessions.models import Session
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

# Create your views here.


class RegisterAPI(APIView):
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

                print("Serializer is valid")
                user = serializer.save()
                password = make_password(data['password'])
                # Save the hashed password
                user = serializer.save(password=password)
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
            return render(request, 'login.html', {'error': 'Invalid credentials'})


class IndexView(View):
    @method_decorator(login_required)
    def get(self, request):
        if request.user.is_authenticated:
            return render(request, 'index.html', {'username': request.user.username})
        else:
            return redirect('/')


logger = logging.getLogger(__name__)


class ForgotView(PasswordResetView):
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
    template_name = 'registration/register.html'

    def get(self, request):
        email = request.GET.get('email')
        email_already_exists = User.objects.filter(email=email).exists()

        return render(request, self.template_name, {'email_exists': email_already_exists})


class PythonQuiz(View):
    def get(self, request):
        # Replace 'Django' with the appropriate category name for your Django quiz
        python_category = Category.objects.get(category_name='Python')
        questions = list(Question.objects.filter(category=python_category))
        answers = list(Answer.objects.all())

        random.shuffle(questions)
        random.shuffle(answers)

        # Calculate the total number of FIB questions
        total_fib_questions = len(
            [q for q in questions if q.question_type == 'FIB'])
        start_quiz = not request.session.get('quiz_started', False)

        # If the quiz should start, store the quiz start time in the session
        if start_quiz:
            request.session['quiz_start_time'] = timezone.now().strftime(
                '%Y-%m-%d %H:%M:%S')
            request.session['quiz_started'] = True
        context = {
            'questions': questions,
            'answers': answers,
            'total_questions': len(questions),
            'total_fib_questions': total_fib_questions,
            'start_quiz': start_quiz,  # Pass this variable to the template
        }
        return render(request, 'python_quiz.html', context)

    def post(self, request):
        # Replace 'Django' with the appropriate category name for your Django quiz
        python_category = Category.objects.get(category_name='Python')
        questions = list(Question.objects.filter(category=python_category))
        answers = list(Answer.objects.all())

        user_answers = []  # Create an empty list to store user answers
        user_score = 0
        total_fib_questions = 0  # Initialize the count of FIB questions attempted
        total_attempted = 0  # Initialize the count of total questions attempted
        total_score = 0  # Initialize the total score

        for question in questions:
            selected_answer_uuid = request.POST.get(
                f'question_{question.uuid}')
            user_input = request.POST.get(f'question_{question.uuid}_input')
            correct_answer = None

            try:
                correct_answer = Answer.objects.get(
                    question=question, is_correct=True)
            except ObjectDoesNotExist:
                # Handle the case where the correct answer doesn't exist
                pass

            if question.question_type == 'FIB':
                # For FIB questions, use user_input directly
                user_answer_text = user_input if user_input else ""
                is_correct = user_input.strip().lower(
                ) == correct_answer.answer.strip().lower() if user_input else False
                if is_correct:
                    total_score += question.score
                    total_fib_questions += 1  # Increment FIB question count
                if user_input:
                    total_attempted += 1  # Increment total questions attempted for FIB
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
                        total_attempted += 1  # Increment total questions attempted for MCQ
                except ObjectDoesNotExist:
                    # Handle the case where the selected answer UUID doesn't exist
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

            # Create a UserAnswer object and save it
            user_answer_obj = UserAnswer.objects.create(
                user=request.user,
                question=question,
                selected_answer=selected_answer,
                is_correct=is_correct,
            )

        # Calculate the percentage based on the total score and the maximum possible score
        max_possible_score = sum([question.score for question in questions])
        if max_possible_score > 0:
            percentage = (total_score / max_possible_score) * 100
        else:
            percentage = 0

        # Store the user's answers, total score, total attempted questions, total FIB questions attempted, and percentage in session variables
        request.session['python_quiz_user_answers'] = user_answers
        request.session['python_quiz_score'] = f"{total_score}/{max_possible_score}"
        request.session['python_quiz_percentage'] = round(percentage, 2)
        request.session['python_quiz_total_fib_questions'] = total_fib_questions

        # Redirect to the results page
        return HttpResponseRedirect(reverse('python_result'))


class PythonResultView(View):
    def get(self, request):
        # Retrieve the user's score, user answers, and total questions attempted from session variables
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
    def get(self, request):
        # Replace 'Django' with the appropriate category name for your Django quiz
        django_category = Category.objects.get(category_name='Django')
        questions = list(Question.objects.filter(category=django_category))
        answers = list(Answer.objects.all())

        random.shuffle(questions)
        random.shuffle(answers)

        # Calculate the total number of FIB questions
        total_fib_questions = len(
            [q for q in questions if q.question_type == 'FIB'])

        context = {
            'questions': questions,
            'answers': answers,
            'total_questions': len(questions),
            'total_fib_questions': total_fib_questions,
        }
        return render(request, 'django_quiz.html', context)

    def post(self, request):
        # Replace 'Django' with the appropriate category name for your Django quiz
        django_category = Category.objects.get(category_name='Django')
        questions = list(Question.objects.filter(category=django_category))
        answers = list(Answer.objects.all())

        user_answers = []  # Create an empty list to store user answers
        user_score = 0
        total_fib_questions = 0  # Initialize the count of FIB questions attempted
        total_attempted = 0  # Initialize the count of total questions attempted
        total_score = 0  # Initialize the total score

        for question in questions:
            selected_answer_uuid = request.POST.get(
                f'question_{question.uuid}')
            user_input = request.POST.get(f'question_{question.uuid}_input')
            correct_answer = None

            try:
                correct_answer = Answer.objects.get(
                    question=question, is_correct=True)
            except ObjectDoesNotExist:
                # Handle the case where the correct answer doesn't exist
                pass

            if question.question_type == 'FIB':
                # For FIB questions, use user_input directly
                user_answer_text = user_input if user_input else ""
                is_correct = user_input.strip().lower(
                ) == correct_answer.answer.strip().lower() if user_input else False
                if is_correct:
                    total_score += question.score
                    total_fib_questions += 1  # Increment FIB question count
                if user_input:
                    total_attempted += 1  # Increment total questions attempted for FIB
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
                        total_attempted += 1  # Increment total questions attempted for MCQ
                except ObjectDoesNotExist:
                    # Handle the case where the selected answer UUID doesn't exist
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

            # Create a UserAnswer object and save it
            user_answer_obj = UserAnswer.objects.create(
                user=request.user,
                question=question,
                selected_answer=selected_answer,
                is_correct=is_correct,
            )

        # Calculate the percentage based on the total score and the maximum possible score
        max_possible_score = sum([question.score for question in questions])
        if max_possible_score > 0:
            percentage = (total_score / max_possible_score) * 100
        else:
            percentage = 0

        # Store the user's answers, total score, total attempted questions, total FIB questions attempted, and percentage in session variables
        request.session['django_quiz_user_answers'] = user_answers
        request.session['django_quiz_score'] = f"{total_score}/{max_possible_score}"
        request.session['django_quiz_percentage'] = round(percentage, 2)
        request.session['django_quiz_total_fib_questions'] = total_fib_questions

        # Redirect to the results page
        return HttpResponseRedirect(reverse('django_result'))


class DjangoResultView(View):
    def get(self, request):
        # Retrieve the user's score, user answers, and total questions attempted from session variables
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
    def get(self, request):
        java_category = Category.objects.get(category_name='JS')
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

    def post(self, request):
        java_category = Category.objects.get(category_name='JS')
        questions = list(Question.objects.filter(category=java_category))
        answers = list(Answer.objects.all())

        user_answers = []  # Create an empty list to store user answers
        user_score = 0
        for question in questions:
            selected_answer_uuid = request.POST.get(
                f'question_{question.uuid}')
            user_input = request.POST.get(f'question_{question.uuid}_input')
            correct_answer = Answer.objects.get(
                question=question, is_correct=True)

            if question.question_type == 'FIB':
                print(f'User input for question {question.uuid}: {user_input}')
                # For FIB questions, use user_input directly
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

            # Create a UserAnswer object and save it
            user_answer_obj = UserAnswer.objects.create(
                user=request.user,
                question=question,
                selected_answer=Answer.objects.get(
                    uuid=selected_answer_uuid) if selected_answer_uuid else None,
                is_correct=is_correct,
            )

        total_attempted = len(questions)

        # Calculate the percentage based on the score and total attempted questions
        if total_attempted > 0:
            percentage = (user_score / total_attempted) * 100
        else:
            percentage = 0

        # Store the user's answers, score, and total attempted questions in session variables
        request.session['java_quiz_user_answers'] = user_answers
        request.session['java_quiz_score'] = f"{user_score}/{total_attempted}"
        request.session['java_quiz_percentage'] = round(percentage, 2)

        # Redirect to the results page
        return HttpResponseRedirect(reverse('java_result'))


class JavaResultView(View):
    def get(self, request):
        # Retrieve the user's score, user answers, and total questions attempted from session variables
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
    def get(self, request):
        logout(request)
        return redirect('/')
