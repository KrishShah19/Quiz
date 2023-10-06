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
from rest_framework import status
from .serializer import UserSerializer
from django.db.models import F
from django.contrib.auth.views import LogoutView as DjangoLogoutView
from django.views import View
from django.views.decorators.cache import never_cache
from django.core.exceptions import ObjectDoesNotExist
from .serializer import SetPasswordSerializer  # Import the SetPasswordSerializer
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.template.loader import render_to_string
from django.http import HttpResponse, JsonResponse
import logging
from django.template import loader
from django.core.mail import EmailMultiAlternatives

User = get_user_model()
logger = logging.getLogger('django')

class SendEmailView(View):
    def post(self, request):
        if request.method == 'POST':
            email = request.POST.get('email')
            print("Email received: ", email)
            print("POST CALLED^^^^^^^^^^^^^^^^^")
            try:
                # Check if a user with the provided email exists
                user, created = User.objects.get_or_create(email=email)

                # Generate a confirmation token
                token = default_token_generator.make_token(user)
                print("^^^^^^^^^^^^TOKEN^^^^^^:", token)
                uid = urlsafe_base64_encode(force_bytes(user.pk))

                # Build the confirmation URL
                confirmation_url = settings.FRONTEND_URL + f'/set_password/{uid}/{token}/'
                print("^^^^^^^^^^^^", confirmation_url)

                # Render the email template
                subject = 'Confirm Your Registration'
                email_template = loader.get_template('registration/email_link_template.html')
                email_context = {
                    'user': user,
                    'confirmation_url': confirmation_url,
                }
                email_content = email_template.render(email_context)

                # Create an EmailMultiAlternatives object for HTML email
                msg = EmailMultiAlternatives(subject, email_content, settings.EMAIL_HOST_USER, [user.email])
                msg.attach_alternative(email_content, "text/html")

                # Send the email
                msg.send()

                print(f"Email sent successfully to {email}")

                return HttpResponseRedirect(reverse('email_sent'))
            except Exception as e:
                print(f"Error sending email: {e}")
                logger.error(f"Error sending email: {e}")
                return JsonResponse({'success': False, 'error_message': str(e)})

            
class EmailSentView(View):
    template_name = 'email_sent.html'  # Update with your actual template name

    def get(self, request):
        return render(request, self.template_name)
    
class SetPasswordView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.filter(pk=uid).first()

            # Initialize a variable to track whether token verification was successful
            token_verified = False

            # If a user with the provided UID exists, proceed with setting the password
            if user:
                # Verify the token
                if default_token_generator.check_token(user, token):
                    token_verified = True
                    # Display the password set form
                    print("Token checked successfully")  # Add this line
                    return render(request, 'registration/set_password.html', {'user': user})

            # Log the result of token verification
            if token_verified:
                print("Token checked successfully")
            else:
                print("Token verification failed")

            # If no user with the provided UID exists or token check fails, handle it accordingly (e.g., show an error)
            return redirect('password_reset_invalid')

        except (TypeError, ValueError, OverflowError):
            user = None

        return redirect('password_reset_invalid')

    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.filter(pk=uid).first()

            # Initialize a variable to track whether token verification was successful
            token_verified = False

            # If a user with the provided UID exists, proceed with setting the password
            if user:
                # Verify the token
                if default_token_generator.check_token(user, token):
                    token_verified = True
                    # Create the SetPasswordSerializer instance and validate data
                    form = SetPasswordSerializer(data=request.POST)
                    if form.is_valid():
                        # Set the new password
                        new_password = form.validated_data['new_password']
                        user.set_password(new_password)
                        user.save()

                        # Log in the user
                        login(request, user)

                        # Redirect to a success page or any other desired page
                        return redirect('login')

            # Log the result of token verification
            if token_verified:
                print("Token checked successfully")
            else:
                print("Token verification failed")

            # If no user with the provided UID exists or token check fails, handle it accordingly (e.g., show an error)
            return redirect('password_reset_invalid')

        except Exception as e:
            user = None
            print(f"Error during token verification: {e}")
            # Log the error
            logger.error(f"Error during token verification: {e}")

        return redirect('password_reset_invalid')


class PasswordResetInvalid(View):
    def get(self, request):
        return render(request, 'password_reset_invalid.html')        
logger = logging.getLogger(__name__)

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

            # Create the user object but don't save it to the database yet
            user = User(email=email)
            
            serializer = UserSerializer(data=data)
            if serializer.is_valid():
                # Generate a confirmation token
                token = default_token_generator.make_token(user)

                # Create a unique token for the user
                uid = urlsafe_base64_encode(force_bytes(user.pk))

                # Build the confirmation URL
                confirmation_url = settings.FRONTEND_URL + f'/set_password/{uid}/{token}/'

                # Create a subject and message for the email
                subject = 'Confirm Your Registration'
                message = render_to_string('registration/email_link_template.html', {
                    'user': user,
                    'confirmation_url': confirmation_url,
                })

                # Send the email
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

                # Save the user to the database
                user.save()

                return Response({
                    'status': 200,
                    'message': 'Registration successful. Check email to set the password.',
                    'data': serializer.data
                })

            return Response({
                'status': 400,
                'message': 'Something went wrong with data validation.',
                'data': serializer.errors
            })
        except Exception as e:
            return Response({
                'status': 400,
                'message': 'Something went wrong.',
                'data': str(e)
            })
        

class RegisterView(View):
    """
    RegisterView: Handles user registration via web interface.
    """
    template_name = 'registration/register.html'

    def get(self, request):
        """
        Display the registration form.
        """
        return render(request, self.template_name)
    
    def post(self, request):
        data = request.POST
        email = data.get('email')
        
        if not email:
        # Handle the case where the email is empty
            return HttpResponse("Email must be provided.", status=400)
        existing_user = User.objects.filter(email=email).first()
        if existing_user:
            return HttpResponse("Email already exists. Please use a different email address.", status=400)
        # Create a new user without checking for email existence
        user = User.objects.create_user(email=email)
        
        # Log in the newly created user
        login(request, user)

        # Redirect to the OTP verification page or any other desired page
        return redirect('login')


class LoginView(View):
    """
    LoginView: Handles user login via web interface.
    """
    template_name = 'login.html'

    def get(self, request):
        """
        Display the login form.
        """
        return render(request, self.template_name)

    def post(self, request):
        """
        Handle user login via web interface.
        """
        email = request.POST.get('email')
        password = request.POST.get('password')

        user = authenticate(email=email, password=password)
        if user is not None:
            login(request, user)
            return redirect('index')
        else:
            return render(request, self.template_name, {'error': 'Invalid credentials'})


class IndexView(View):
    """
    IndexView: Handles the main index page.
    """
    template_name = 'index.html'

    @method_decorator(login_required)
    @method_decorator(never_cache)
    def get(self, request):
        """
        Display the main index page for authenticated users.
        """
        if request.user.is_authenticated:
            return render(request, self.template_name, {'username': request.user.username})
        else:
            return redirect('/')


class AddQuizView(View):
    template_name = 'add_quiz.html'  # The template where you have the form

    def get(self, request):
        # Retrieve categories and answers from the database
        categories = Category.objects.all()
        answers = Answer.objects.all()
        context = {
            'categories': categories,
            'answers': answers,
        }
        return render(request, self.template_name, context)

    def post(self, request):
        # Handle the form submission
        category_id = request.POST.get('category')
        question_text = request.POST.get('question')
        question_type = request.POST.get('question_type')
        score = request.POST.get('score')

        # Create a new question
        question = Question.objects.create(
            category_id=category_id,
            text=question_text,
            question_type=question_type,
            score=score
        )

        if question_type == 'MCQ':
            # For Multiple Choice Questions
            answer_ids = [int(request.POST.get(f'answer{i}')) for i in range(1, 6)]  # Adjust the range as needed

            for answer_id in answer_ids:
                answer = Answer.objects.get(id=answer_id)
                question.answers.add(answer)

            correct_answer_ids = request.POST.getlist('correct_answer')
            for correct_id in correct_answer_ids:
                correct_answer = Answer.objects.get(id=correct_id)
                question.correct_answers.add(correct_answer)

        elif question_type == 'FIB':
            # For Fill in the Blank Questions
            correct_answer_text = request.POST.get('correct_answer')

            # Create and set the correct answer
            correct_answer = Answer.objects.create(answer=correct_answer_text)
            question.correct_answers.add(correct_answer)

        # Redirect to a success page or wherever you'd like
        return redirect('index')  # Adjust the URL name
    
# class ForgotView(PasswordResetView):
#     """
#     ForgotView: Handles password reset via web interface.
#     """
#     template_name = 'forgot.html'

#     def get(self, request):
#         """
#         Display the password reset form.
#         """
#         return render(request, self.template_name)

#     def post(self, request):
#         """
#         Handle password reset via web interface.
#         """
#         data = request.POST
#         email = data.get('email')
#         if send_otp(email):
#             messages.success(request, 'OTP has been sent to your email.')
#             verify_otp_url = reverse('verify_otp', args=[email])
#             logger.info(f"OTP sent to {email}")
#             return HttpResponseRedirect(verify_otp_url)
#         else:
#             messages.error(
#                 request, 'Failed to send OTP. Please try again later.')
#             return render(request, self.template_name, {'error_message': 'Failed to send OTP. Please try again later.'})


class VerifyOTPView(PasswordResetView):
    """
    VerifyOTPView: Handles OTP verification via web interface.
    """
    template_name = 'registration/verify_otp.html'

    def get(self, request):
        """
        Display the OTP verification form.
        """
        return render(request, self.template_name)

    def post(self, request):
        """
        Handle OTP verification via web interface.
        """
        data = request.POST
        email = data.get('email')
        otp = data.get('otp')

        user = User.objects.filter(email=email, otp=otp).first()
        if user:
            user.is_verified = True
            user.save()
            login(request, user)
            messages.success(request, 'OTP verified successfully!')
            return redirect('index')
        else:
            messages.error(request, 'Incorrect OTP. Please try again.')
            return render(request, self.template_name)


class QuizViewBase(View):
    """
    Base class for quiz views.
    """
    template_name = None

    def get(self, request):
        """
        Display the quiz page.
        """
        category = self.get_category()
        if request.session.get(f'{self.quiz_type}_completed'):
            messages.warning(request, f"You've already completed the {self.quiz_type} quiz.")
            return redirect(f'{self.quiz_type}_result')
        
        questions = list(Question.objects.filter(category=category))
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
            'completed_quiz': completed_quizzes,
        }
        return render(request, self.template_name, context)

    def post(self, request):
        """
        Handle quiz submission.
        """
        category = self.get_category()
        if request.session.get(f'{self.quiz_type}_completed'):
            messages.warning(request, f"You've already completed the {self.quiz_type} quiz.")
            return redirect(f'{self.quiz_type}_result')
        
        questions = list(Question.objects.filter(category=category))
        answers = list(Answer.objects.all())

        user_answers = []
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
        
        request.session[f'{self.quiz_type}_completed'] = True

        if total_categories > 0:
            progress_percentage = (completed_quizzes / total_categories) * 100.0
        else:
            progress_percentage = 0.0

        request.session['quiz_progress_percentage'] = progress_percentage
        request.session[f'{self.quiz_type}_user_answers'] = user_answers
        request.session[f'{self.quiz_type}_score'] = f"{total_score}/{max_possible_score}"
        request.session[f'{self.quiz_type}_percentage'] = round(percentage, 2)
        request.session[f'{self.quiz_type}_total_fib_questions'] = total_fib_questions

        return HttpResponseRedirect(reverse(f'{self.quiz_type}_result'))

class PythonQuiz(QuizViewBase):
    """
    PythonQuizView: Handles the Python quiz page.
    """
    template_name = 'python_quiz.html'

    def get_category(self):
        return Category.objects.get(category_name='Python')

    @property
    def quiz_type(self):
        return 'python'
    
    def get(self, request):
        """
        Display the Python quiz page.
        """
        # Check if the user has already completed the Python quiz
        if request.session.get(f'{self.quiz_type}_completed'):
            messages.warning(request, f"You've already completed the {self.quiz_type} quiz.")
            return redirect(f'{self.quiz_type}_result')

        return super().get(request)

    def post(self, request):
        """
        Handle Python quiz submission.
        """
        # Check if the user has already completed the Python quiz
        if request.session.get(f'{self.quiz_type}_completed'):
            messages.warning(request, f"You've already completed the {self.quiz_type} quiz.")
            return redirect(f'{self.quiz_type}_result')

        return super().post(request)

class PythonResultView(View):
    """
    PythonResultView: Handles the Python quiz result page.
    """
    template_name = 'python_result.html'

    def get(self, request):
        """
        Display the Python quiz result.
        """
        score = request.session.get('python_score', '0/0')
        user_answers = request.session.get('python_user_answers', [])
        total_questions_attempted = len(user_answers)
        total_fib_questions = request.session.get('python_total_fib_questions', 0)
        percentage = request.session.get('python_percentage', 0)
        progress_percentage = request.session.get(
            'quiz_progress_percentage', 0)

        return render(request, self.template_name, {
            'score': score,
            'user_answers': user_answers,
            'total_questions_attempted': total_questions_attempted,
            'total_fib_questions': total_fib_questions,
            'percentage': percentage,
            'progress_percentage': progress_percentage,
        })

class JavaScriptQuiz(QuizViewBase):
    """
    JavaScriptQuizView: Handles the JavaScript quiz page.
    """
    template_name = 'javascript_quiz.html'

    def get_category(self):
        return Category.objects.get(category_name='JS')

    @property
    def quiz_type(self):
        return 'javascript'
    
    def get(self, request):
        """
        Display the Python quiz page.
        """
        # Check if the user has already completed the Python quiz
        if request.session.get(f'{self.quiz_type}_completed'):
            messages.warning(request, f"You've already completed the {self.quiz_type} quiz.")
            return redirect(f'{self.quiz_type}_result')

        return super().get(request)

    def post(self, request):
        """
        Handle Python quiz submission.
        """
        # Check if the user has already completed the Python quiz
        if request.session.get(f'{self.quiz_type}_completed'):
            messages.warning(request, f"You've already completed the {self.quiz_type} quiz.")
            return redirect(f'{self.quiz_type}_result')

        return super().post(request)

class JavaScriptResultView(View):
    """
    JavaScriptResultView: Handles the JavaScript quiz result page.
    """
    template_name = 'javascript_result.html'

    def get(self, request):
        """
        Display the JavaScript quiz result.
        """
        score = request.session.get('javascript_score', '0/0')
        user_answers = request.session.get('javascript_user_answers', [])
        total_questions_attempted = len(user_answers)
        total_fib_questions = request.session.get('javascript_total_fib_questions', 0)
        percentage = request.session.get('javascript_percentage', 0)
        progress_percentage = request.session.get(
            'quiz_progress_percentage', 0)

        return render(request, self.template_name, {
            'score': score,
            'user_answers': user_answers,
            'total_questions_attempted': total_questions_attempted,
            'total_fib_questions': total_fib_questions,
            'percentage': percentage,
            'progress_percentage': progress_percentage,
        })

class DjangoQuizView(QuizViewBase):
    """
    DjangoQuizView: Handles the Django quiz page.
    """
    template_name = 'django_quiz.html'

    def get_category(self):
        return Category.objects.get(category_name='Django')

    @property
    def quiz_type(self):
        return 'django'
    
    def get(self, request):
        """
        Display the Python quiz page.
        """
        # Check if the user has already completed the Python quiz
        if request.session.get(f'{self.quiz_type}_completed'):
            messages.warning(request, f"You've already completed the {self.quiz_type} quiz.")
            return redirect(f'{self.quiz_type}_result')

        return super().get(request)

    def post(self, request):
        """
        Handle Python quiz submission.
        """
        # Check if the user has already completed the Python quiz
        if request.session.get(f'{self.quiz_type}_completed'):
            messages.warning(request, f"You've already completed the {self.quiz_type} quiz.")
            return redirect(f'{self.quiz_type}_result')

        return super().post(request)

class DjangoResultView(View):
    """
    DjangoResultView: Handles the Django quiz result page.
    """
    template_name = 'django_result.html'

    def get(self, request):
        """
        Display the Django quiz result.
        """
        score = request.session.get('django_score', '0/0')
        user_answers = request.session.get('django_user_answers', [])
        total_questions_attempted = len(user_answers)
        total_fib_questions = request.session.get('django_total_fib_questions', 0)
        percentage = request.session.get('django_percentage', 0)
        progress_percentage = request.session.get(
            'quiz_progress_percentage', 0)

        return render(request, self.template_name, {
            'score': score,
            'user_answers': user_answers,
            'total_questions_attempted': total_questions_attempted,
            'total_fib_questions': total_fib_questions,
            'percentage': percentage,
            'progress_percentage': progress_percentage,
        })

class LogoutView(DjangoLogoutView):
    """
    LogoutView: Handles user logout.
    """
    next_page='/'
    def dispatch(self, request, *args, **kwargs):
        request.session.flush()
        return super().dispatch(request, *args, **kwargs)