# from django.core.mail import send_mail
# import random
# from django.conf import settings
# from django.core.exceptions import ObjectDoesNotExist
# from .models import User
# import traceback
# def send_otp(email):
#     subject = 'Your Account Verification Email'
#     otp = random.randint(1000,9999)
#     message = f'Your Account Verification code is {otp}'
#     email_from = settings.EMAIL_HOST_USER

#     print(f"Sending OTP to: {email}")
#     print(f"OTP: {otp}")

#     try:
#         send_mail(subject, message, email_from, [email])
#         print("Sent OTP CALLED")
#         try:
#             user_obj = User.objects.get(email=email)
#             user_obj.otp = otp
#             user_obj.save()
#             return True
#         except ObjectDoesNotExist:
#             # Handle the case where the user doesn't exist
#             return False
#     except Exception as e:
#         traceback.print_exc()  # Print the exception traceback for debugging
#         print(f"An error occurred while sending the OTP email: {e}")
#         return str(e)  # Return the exception as a string for debugging


from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import reverse
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

def send_password_reset_link(request, user):
    # Generate a password reset token for the user
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))

    # Construct the password reset URL
    reset_url = reverse('set_password', args=[uid, token])

    subject = 'Password Reset'
    message = f'Click the link below to reset your password:\n\n{request.build_absolute_uri(reset_url)}'
    email_from = settings.EMAIL_HOST_USER
    print(f"Sending mail to: {user.email}")
    print(f"Email Content:")
    try:
        send_mail(subject, message, email_from, [user.email])
        print("Sent mail CALLED")
        return True
    except Exception as e:
        print(f"An error occurred while sending the password reset email: {e}")
        return False

