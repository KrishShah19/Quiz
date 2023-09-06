from django import forms

class QuizSubmissionForm(forms.Form):
    all_questions_attempted = forms.BooleanField(widget=forms.HiddenInput(), required=False)
