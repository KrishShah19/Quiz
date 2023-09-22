# # admin.py

# from django.contrib import admin
# from django.contrib.auth import get_user_model
# from .models import *

# admin.site.register(User)
# admin.site.register(Category)
# admin.site.register(Answer)
# admin.site.register(UserAnswer)
# admin.site.register(QuizProgress)

# class AnswerAdmin(admin.StackedInline):
#     model = Answer

# @admin.register(Question)
# class QuestionAdmin(admin.ModelAdmin):
#     inlines = [AnswerAdmin]

from django.contrib import admin
from nested_admin import NestedTabularInline, NestedModelAdmin
from .models import *

class AnswerInline(NestedTabularInline):
    model = Answer
    extra = 1

class QuestionInline(NestedTabularInline):
    model = Question
    inlines = [AnswerInline]
    extra = 1

@admin.register(Category)
class CategoryAdmin(NestedModelAdmin):
    inlines = [QuestionInline]
    list_display = ('category_name',)
    search_fields = ('category_name',)

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'is_verified')
    list_filter = ('is_verified',)
    search_fields = ('username', 'email')

@admin.register(UserAnswer)
class UserAnswerAdmin(admin.ModelAdmin):
    list_display = ('user', 'question_text', 'selected_answer_text', 'is_correct')
    list_filter = ('user', 'question__category', 'is_correct')
    search_fields = ('user__username', 'question__question', 'selected_answer__answer')

    def question_text(self, obj):
        return obj.question.question
    
    def selected_answer_text(self, obj):
        if obj.selected_answer:
            return obj.selected_answer.answer
        return "N/A"

    question_text.short_description = 'Question'
    selected_answer_text.short_description = 'Selected Answer'
    

@admin.register(QuizProgress)
class QuizProgressAdmin(admin.ModelAdmin):
    list_display = ('user', 'category', 'timer_state', 'last_activity')
    list_filter = ('category',)
    search_fields = ('user__username', 'category__category_name')

admin.register(Question)
admin.register(Answer)