from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    display_name = models.CharField(max_length=255, blank=True)
    email = models.EmailField(unique=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'display_name']

    def __str__(self):
        return self.display_name or self.email