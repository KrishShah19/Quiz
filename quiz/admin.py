# admin.py

from django.contrib import admin
from django.contrib.auth import get_user_model
from .models import User, Category, Answer, Question

admin.site.register(User)
admin.site.register(Category)
admin.site.register(Answer)

class AnswerAdmin(admin.StackedInline):
    model = Answer

@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    inlines = [AnswerAdmin]
