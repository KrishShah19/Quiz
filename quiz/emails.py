from django.core.mail import send_mail
import random
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from .models import User

def send_otp(email):
    subject = 'Your Account Verification Email'
    otp = random.randint(0,1)
    message = f'Your otp is {otp}'
    email_from = settings.EMAIL_HOST_USER

    print(f"Sending OTP to: {email}")
    print(f"OTP: {otp}")

    try:
        send_mail(subject, message, email_from, [email])
        try:
            user_obj = User.objects.get(email=email)
            user_obj.otp = otp
            user_obj.save()
            return True
        except ObjectDoesNotExist:
            # Handle the case where the user doesn't exist
            return False
    except Exception as e:
        print(f"An error occurred while sending the OTP email: {e}")
        return False

