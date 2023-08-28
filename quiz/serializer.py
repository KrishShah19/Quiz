from .models import User
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields=['username','email', 'password','is_verified']

class VerifyAccount(serializers.Serializer):
    email=serializers.EmailField()
    otp=serializers.CharField()

