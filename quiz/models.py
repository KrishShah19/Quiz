import random
from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from .manager import UserManager
import uuid


class User(AbstractUser):
    username = models.CharField(max_length=30, unique=True)
    is_verified = models.BooleanField(default=False)
    otp = models.CharField(max_length=4  , null=True, blank=True)
   
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']
    
    objects = UserManager()
    
    def __str__(self):
        return self.username


class BaseModel(models.Model):
    uuid= models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    cretead_at=models.DateTimeField(auto_now=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract=True

class Category(BaseModel):
    category_name = models.CharField(max_length=100)

    def __str__(self) -> str:
        return self.category_name

class Question(BaseModel):
    # QUESTION_TYPES = [
    #     ('MCQ', 'Multiple Choice Question'),
    #     ('FIB', 'Fill in the Blanks'),
    # ]
    category=models.ForeignKey(Category,related_name='category', on_delete=models.CASCADE)
    question=models.CharField(max_length=100)
    # question_type = models.CharField(max_length=3, choices=QUESTION_TYPES)
    marks=models.IntegerField(default=1)

    def __str__(self) -> str:
        return self.question
    
    def get_answers(self):
        answer_objs=list(Answer.objects.filter(question=self))
        random.shuffle(answer_objs)
        data=[]
        
class Answer(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    question = models.ForeignKey(Question,related_name='question_answer', on_delete=models.CASCADE)
    answer=models.CharField(max_length=100)
    # chosen_option = models.ForeignKey(Option, on_delete=models.CASCADE, null=True, blank=True)
    is_correct = models.BooleanField(default=False)

    def __str__(self) -> str:
        return self.answer
    
# class UserResponse(BaseModel):
#     user
#     question_id
#     answer 
#     is_correct


#     def __str__(self) -> str:
#         return f"{self.user.username} - {self.question.question}"