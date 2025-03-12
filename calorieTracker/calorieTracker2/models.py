from django.db import models
from django.core.validators import EmailValidator
from django.contrib.auth.models import AbstractUser

class Users(AbstractUser):
    email = models.EmailField(validators=[EmailValidator()], unique=True, null=False)

    password = models.CharField(max_length=12, unique=False)
    age = models.CharField(max_length=2)
    weight = models.CharField(max_length=3, unique=False)
    gender = models.CharField(max_length=6, unique=False)
    first_name = models.CharField(max_length=15, unique=False)
    height = models.CharField(max_length=15, unique=False)
    token = models.CharField(max_length=100, unique=False)
    goals = models.CharField(max_length=100, unique=False)
    first_time_login = models.CharField(max_length=100, unique=False)
    target_weight = models.CharField(max_length=3, unique=False)
    target_calories = models.CharField(max_length=1000, unique=False )
    target_protein = models.CharField(max_length=1000, unique=False)
    target_carbs = models.CharField(max_length=1000, unique= False )
    target_fat = models.CharField(max_length=1000, unique=False)

    USERNAME_FIELD = 'email'  # Use email as the username field
    REQUIRED_FIELDS = []  # Do not include 'username' here, because email is the username field

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self.email  # Set username to be the same as email
        super(Users, self).save(*args, **kwargs)

    def __str__(self):
        return self.email
    

class FoodItem(models.Model):
    name = models.CharField(max_length=255)
    calories_per_serving = models.IntegerField()

class CalorieLog(models.Model):
    email = models.EmailField(unique=False)
    name = models.CharField(max_length=20, unique=False ,null = True)
    grams = models.CharField(max_length=4, unique=False ,null = True)
    calories = models.CharField(max_length=4, unique=False ,null = True)
    protein = models.CharField(max_length=4, unique=False, null = True)
    carbs = models.CharField(max_length=4, unique=False,null = True)
    fat = models.CharField(max_length=4, unique=False ,null = True)
    date = models.DateField(auto_now_add=True ,null = True)
    total_calories = models.CharField( max_length = 50, unique=False, null=True)


class DailyGoals(models.Model):
    email = models.EmailField(unique=True)  # Store user's email
    target_calories = models.IntegerField()
    target_carbs = models.IntegerField()
    target_fat = models.IntegerField()
    target_protein = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.email}'s Daily Goals"
    
class TotalCalories(models.Model):
    email = models.EmailField(unique=False)
    total_calories = models.IntegerField(default=0)
    date = models.DateField(auto_now_add=True, null=True)

class UserLogoutData(models.Model):
    total_calories = models.CharField(max_length=4, unique=False, null = True)
    email = models.CharField(max_length=4, unique=False,  null = True)
    date = models.DateField(auto_now_add=True, null=True)