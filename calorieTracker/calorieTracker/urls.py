"""
URL configuration for calorieTracker project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from calorieTracker2.views import RegisterEmailView
from calorieTracker2.views import RegisterEmailAndPassword
from calorieTracker2.views import RegisterDetailsView
from calorieTracker2.views import LoginEmail
from calorieTracker2.views import LoginEmailandPassword
from calorieTracker2.views import firebase_token
from calorieTracker2.views import LogoutView
from calorieTracker2.views import RegisterGoals
from calorieTracker2.views import RegisterDailyGoals
from calorieTracker2.views import RegisterFood
urlpatterns = [
    path('admin/', admin.site.urls),

    path('api/register_email/', RegisterEmailView.as_view(), name = "register"),
    path('api/register_details/', RegisterEmailAndPassword.as_view(), name = "register2" ),
    path("api/register_profile/", RegisterDetailsView.as_view(), name = "register_profile"),
    path("api/login/", LoginEmail.as_view(), name = "login"),
    path("api/validate_user/", LoginEmailandPassword.as_view(), name = "login2"),
    path('api/auth/token/', firebase_token.as_view(), name='verify_firebase_token'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path('api/register_goals', RegisterGoals.as_view(), name = "Register"),
    path("api/register_daily_goals/", RegisterDailyGoals.as_view(), name = "register_daily_goals"),
    path('api/register_food', RegisterFood.as_view(), name = "register_food")
]
