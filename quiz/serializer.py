from .models import User
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields=['email','is_verified']
    def validate_email(self, value):
        """
        Check if the email is already associated with an existing user.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Email already exists.')
        return value

class SetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(style={'input_type': 'password'})
    confirm_password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, data):
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        if new_password != confirm_password:
            raise serializers.ValidationError("Passwords do not match.")

        return data

# from django import forms
# from .models import Quiz

# class QuizForm(forms.ModelForm):
#     class Meta:
#         model = Quiz
#         fields = ['category', 'questions', 'answers', 'question_type', 'correct_answer', 'score', 'user']

#     def set_password(self, user):
#         new_password = self.validated_data.get('new_password')
#         user.set_password(new_password)
#         user.save()
