from django import forms
from django.contrib.auth.models import User


class CreateUserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username','email', 'password']

    def save(self, commit=True) -> User:
        user = super().save(commit=False)
        user.username = self.cleaned_data["username"]
        user.email = self.cleaned_data["email"]
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user
    
