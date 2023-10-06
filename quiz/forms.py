from django import forms
from .models import *
class QuizSubmissionForm(forms.Form):
    all_questions_attempted = forms.BooleanField(widget=forms.HiddenInput(), required=False)

class QuizForm(forms.ModelForm):
    class Meta:
        model = Question
        fields = ['question', 'question_type',  'score']
