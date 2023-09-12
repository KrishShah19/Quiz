from .models import User
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields=['username','email', 'password','is_verified']
    def validate_email(self, value):
        """
        Check if the email is already associated with an existing user.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Email already exists.')
        return value

class VerifyAccount(serializers.Serializer):
    email=serializers.EmailField()
    otp=serializers.CharField()

