from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from datetime import date
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from rest_framework.permissions import AllowAny
from django.core.exceptions import ValidationError
from .models import TotalCalories
from django.db.models import Sum
from django.contrib.auth.hashers import make_password
from rest_framework.authtoken.models import Token
from .models import CalorieLog
from rest_framework.permissions import IsAuthenticated

from calorieTracker2.models import Users

import requests
import json
from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Users  # Ensure this is the correct model
from .models import DailyGoals

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import DailyGoals

from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate

from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User  # Or your custom user model (Users)




from django.http import JsonResponse
# Create your views here.

class RegisterEmailView(APIView):

    def post(self, request):
        # Get the email from the request data
        email = request.data.get('email')

        # Case 1: If the email is missing in the request
        if not email:
            return Response(
                {'error': 'Email is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Case 2: Validate the email format

         if Users.objects.filter(email=email).exists():
             return Response({
              "message": "email already exists",
             } ,
             status= status.HTTP_400_BAD_REQUEST
             )
         else:
            validate_email(email)
            request.session["email"] = email
        except ValidationError:
            # If the email is not valid, return a 400 Bad Request
            return Response(
                {'error': 'Invalid email format'},
                status=status.HTTP_400_BAD_REQUEST
            )
        

        # Case 3: If the email is valid, return a success response
        return Response(
            {'message': 'Email registered successfully'},
            status=status.HTTP_201_CREATED
        )
    
    



class RegisterEmailAndPassword(APIView):

    def post(self, request):

        email = request.data.get("email")
        password = request.data.get("password")

        if not email and password:
            return Response(
            {"error": "Email and password is required"},
            status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            validate_email(email)
            validate_password(password)

            request.session["email"] = email
            request.session["password"] = password
        except ValidationError:
            return Response({"Password is not valid"},
                        status = status.HTTP_400_BAD_REQUEST
                            )
        
        return Response({
         "Message": "Email and Password succefully registered",},
         status = status.HTTP_201_CREATED 
        )
    

class RegisterDetailsView(APIView):

    def post(self, request):

        email = request.data.get('email')
        password = request.data.get('password')
        height = request.data.get("height")
        weight = request.data.get('weight')
        age = request.data.get('age')
        gender = request.data.get('gender')
        first_name = request.data.get('firstName')

        # Validate that all fields are provided
        if not all([email, password, height, weight, age, gender, first_name]):
            return Response(
                {"error": "All fields are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if the email already exists
        if Users.objects.filter(email=email).exists():
            return Response(
                {"error": "Email already exists"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Create a new user object
            user = Users.objects.create(
                email=email,
                password= make_password(password),  # Ensure this is hashed before saving
                height=height,
                weight=weight,
                age=age,
                gender=gender,
                first_name=first_name
            )

            # Hash password before saving it (assuming `Users` is a custom model)
            user.save()

            return Response(
                {"message": "User is successfully created"},
                status=status.HTTP_201_CREATED  # HTTP 201 for successful creation
            )

        except ValidationError as e:
            return Response(
                {"error": str(e)},  # Provide error details
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LoginEmail(APIView):

    def post(self, request):

        email = request.data.get('email')
        
        if not email:
         return Response({'message': 'Email is required.'}, status=400)
        if not Users.objects.filter(email=email).exists():
         return Response({'message': 'Email not registered.'}, status=404)
        return Response({'message': 'Email is valid.'}, status=200)




class LoginEmailandPassword(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({'message': 'Email and Password are required'}, status=400)

        try:
            today = date.today()

            # Fetch the user
            user = Users.objects.get(email=email)

            # Fetch user's daily goals (if exist)
            user_goals = DailyGoals.objects.filter(email=user.email).first()

            # Calculate total calories for today
            total_calories = TotalCalories.objects.filter(email=email, date=today).distinct().aggregate(Sum('total_calories'))['total_calories__sum'] or 0

            if check_password(password, user.password):
                # Generate or get the token for this user
                token, created = Token.objects.get_or_create(user=user)

                response_data = {
                    'message': 'Login successful',
                    'token': token.key,
                    'first_name': user.first_name,
                    'first_time_login': user.first_time_login,
                    'goals': user.goals,
                    "total_calories": total_calories,
                }

                # If user has daily goals, add them to the response
                if user_goals:
                    response_data.update({
                        "calories": user_goals.target_calories,
                        "carbs": user_goals.target_carbs,
                        "fat": user_goals.target_fat,
                        "protein": user_goals.target_protein
                    })
                else:
                    response_data.update({
                        "calories": None,
                        "carbs": None,
                        "fat": None,
                        "protein": None
                    })

                return Response(response_data, status=200)
            else:
                return Response({'message': 'Invalid email or password'}, status=401)

        except Users.DoesNotExist:
            return Response({'message': 'Invalid email or password'}, status=401)

FIREBASE_API_KEY = 'AIzaSyD82PeS3ZcnQ1pKT1N74cTRudI92hN1b_E'  # Replace with your Firebase API key
class firebase_token(APIView):
    def verify_firebase_token(request):
        if request.method == "POST":
            try:
                # Parse token from request body
                data = json.loads(request.body)
                token = data.get('token')

                if not token:
                    return JsonResponse({'error': 'Token is missing'}, status=400)

                # Firebase ID token verification URL
                url = f'https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={FIREBASE_API_KEY}'

                # Send request to Firebase API to verify the token
                response = requests.post(url, json={'idToken': token})

                # Check if the response was successful
                if response.status_code == 200:
                    # Firebase returns the decoded token in the response
                    decoded_token = response.json()
                    uid = decoded_token['users'][0]['localId']
                    return JsonResponse({'message': 'Token is valid', 'uid': uid})

                else:
                    return JsonResponse({'error': 'Token verification failed', 'details': response.json()}, status=400)

            except Exception as e:
                return JsonResponse({'error': str(e)}, status=400)
        return JsonResponse({'error': 'Invalid request'}, status=400)


class LoginToken(APIView):
    def create_user_and_token(email, password):
        user = Users.objects.get(email=email)  # Fetch existing user
        token, created = Token.objects.get_or_create(user=user)  # Get/Create token

        # Fetch user goals
        user_goals = DailyGoals.objects.filter(user=user).first()
        target_calories = user_goals.target_calories if user_goals else 0
        target_fat = user_goals.target_fat if user_goals else 0
        target_protein = user_goals.target_protein if user_goals else 0
        target_carbs = user_goals.target_carbs if user_goals else 0

        # Fetch today's calories
        today = date.today()
        user_calories = TotalCalories.objects.filter(email=email, date=today).first()
        total_calories = user_calories.total_calories if user_calories else 0

        return Response({
            "token": token.key,
            "user_id": user.id,
            "email": user.email,
            "calories": target_calories,  
            "fat": target_fat,
            "protein": target_protein,
            "carbs": target_carbs,
            "total_calories": user_calories  # Today's total calories
        })

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        token = request.auth  # Get the token
        email = request.user.email  # Get user email
        calories = request.data.get('calories')

        # Ensure calories are provided
        if calories is None:
            return Response({'error': 'Calories value is required'}, status=400)

        try:
            # Clean and convert calories to an integer
            calories = int(re.sub(r"[^\d]", "", str(calories)))

            # Get today's date
            today = date.today()

            # Get or create a calorie log entry for today
            calorie_log, created = CalorieLog.objects.get_or_create(email=email, date=today)

            # Convert stored calories to int and add new calories
            calorie_log.calories = int(calorie_log.calories) + calories
            calorie_log.save()

        except ValueError:
            return Response({'error': 'Invalid calorie format'}, status=400)

        # Log the user out by deleting the token
        if token:
            token.delete()
            return Response({'message': 'Logout successful, calories saved'}, status=200)

        return Response({'message': 'No token found. Already logged out.'}, status=400)



class RegisterGoals(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Extract goal from request data
        goal = request.data.get("goal", "").strip()
        first_name = request.data.get("first_name", "").strip()
        print(f"Received goal: {goal}, First Name: {first_name}")  # Debugging

        # Validate goal
        if not goal:
            return Response(
                {"error": "Goal cannot be empty."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Save goal to the user
        user = request.user

        # Ensure `goals` field exists in the User model
        if not hasattr(user, "goals"):
            return Response(
                {"error": "User model does not have a 'goals' field."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        user.goals = goal  
        user.first_time_login = "true"  # Mark first-time login as completed
        user.save()

        print(f"User: {user}, First-time login: {user.first_time_login}")  # Debugging

        return Response(
            {
                "success": "Goal saved successfully!", 
                "goal": user.goals,
                "first_time_login": "true", 
            },
            status=status.HTTP_200_OK
        )



class RegisterDailyGoals(APIView):
    def post(self, request):
        email = request.data.get('email')  # Get user email
        daily_calories = request.data.get('target_calories')
        target_fat = request.data.get('target_fat')
        target_carbs = request.data.get('target_carbs')
        target_protein = request.data.get('target_protein')

        # Check if all required fields are provided
        if None in [email, daily_calories, target_fat, target_carbs, target_protein]:
            return Response({"error": "Please provide all required fields."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Check if DailyGoals with this email exists, if not, create one
            daily_goals, created = DailyGoals.objects.update_or_create(
                email=email,  # Use email to look up or create DailyGoals
                defaults={
                    "target_calories": daily_calories,
                    "target_carbs": target_carbs,
                    "target_fat": target_fat,
                    "target_protein": target_protein
                }
            )

            if created:
                message = "New daily goals successfully saved."
            else:
                message = "Daily goals successfully updated."

            return Response({"success": message}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



import re  # Import regex module
from datetime import date
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Users, CalorieLog


class RegisterFood(APIView):
    def post(self, request):
        print("Received Request Data:", request.data)

        email = request.data.get('email', '').strip()
        name = request.data.get('name', '').strip()
        calories = request.data.get('calories', '').strip()
        fat = request.data.get('fat', '').strip()
        grams = request.data.get('grams', '').strip()
        carbs = request.data.get('carbs', '').strip()
        protein = request.data.get('protein', '').strip()

        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        if not all([name, calories, fat, grams, carbs, protein]):
            print("Validation Failed: Missing required fields")
            return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        def clean_number(value):
            return re.sub(r"[^\d.]", "", value)

        try:
            calories = int(clean_number(calories))
            fat = float(clean_number(fat))
            grams = float(clean_number(grams))
            carbs = float(clean_number(carbs))
            protein = float(clean_number(protein))
        except ValueError:
            print("Validation Failed: Invalid number format")
            return Response({"error": "Invalid number format"}, status=status.HTTP_400_BAD_REQUEST)

        today = date.today()

        # Fetch existing record or create new one
        calorie_log, created = CalorieLog.objects.get_or_create(email=email, date=today)

        # Convert stored values to correct types before adding
        calorie_log.calories = int(calorie_log.calories) + calories
        calorie_log.fat = float(calorie_log.fat) + fat
        calorie_log.grams = float(calorie_log.grams) + grams
        calorie_log.carbs = float(calorie_log.carbs) + carbs
        calorie_log.protein = float(calorie_log.protein) + protein
        calorie_log.name = name  # Update name if needed
        calorie_log.save()

        # **Update Total Calories in Separate Table**
        total_calories_log, _ = TotalCalories.objects.get_or_create(email=email, date=today)
        total_calories_log.total_calories += calories
        total_calories_log.save()

        return Response({
            "message": "Calorie log updated successfully" if not created else "New calorie log created",
            "log": {
                "name": calorie_log.name,
                "calories": calorie_log.calories,
                "fat": calorie_log.fat,
                "grams": calorie_log.grams,
                "carbs": calorie_log.carbs,
                "protein": calorie_log.protein,
                "date": calorie_log.date.strftime("%Y-%m-%d")
            },
            "total_calories": total_calories_log.total_calories  # Include updated total
        }, status=status.HTTP_200_OK)
class RegisterTotalCalories(APIView):

    def post(self, request):

        email = request.data.get('email')

        if not email:
            return Response({})
