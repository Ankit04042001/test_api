from django.db import models
from django.contrib.auth.models import AbstractUser
from .manager import CustomUserManager
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from datetime import timedelta

class User(AbstractUser):
    email = models.EmailField(blank=False, null=False, unique=True, error_messages={'blank':'It is working'})
    mobile_no = models.CharField(max_length=10, blank=True, null=True, default='')
    USERNAME_FIELD = 'email'
    objects = CustomUserManager()
    
    REQUIRED_FIELDS = ['first_name', 'last_name', 'mobile_no']

    def __str__(self):
        return self.email

    


class Attendence(models.Model):
    attendence_status_choices = [
        ('P', 'Present'), 
        ('A', 'Absent'),
        # ('N', 'Pending'),
    ]
    date = models.DateField(auto_now=False, auto_now_add=False, blank=False, null=False, default=timezone.now)
    punch_in = models.TimeField(auto_now=False, auto_now_add=False, blank=True, null=True)
    # punch_out = models.TimeField(auto_now=False, auto_now_add=False, blank=True, null=True)
    user = models.ForeignKey(User, on_delete = models.CASCADE, unique_for_date="date", default='')
    attendence_status = models.CharField(max_length=1, choices = attendence_status_choices, default = 'A')

    def __str__(self):
        return self.attendence_status

class Task(models.Model):
    task_heading = models.CharField(max_length = 100)
    task_description = models.TextField()

    def __str__(self):
        return self.task_heading


class Otp(models.Model):
    user = models.OneToOneField(User, on_delete = models.CASCADE)
    otp = models.CharField(max_length=6)
    duration = models.DurationField(default = timedelta(seconds=300))
