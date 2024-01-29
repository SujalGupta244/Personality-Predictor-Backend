# from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from datetime import datetime, timedelta
# from django.db import connection
from joblib import load
# import pickle
from django.views.decorators.csrf import csrf_exempt
# # Create your views here.
import json
from bson import ObjectId

from .models import users_collection

from decouple import config

import bcrypt
# import hashlib
import jwt

# def hash_password(password):
#     # Choose a hashing algorithm (e.g., SHA-256)
#     hash_algorithm = hashlib.sha256()

#     # Update the hash object with the password encoded as bytes
#     hash_algorithm.update(password.encode('utf-8'))

#     # Get the hexadecimal representation of the hash
#     hashed_password = hash_algorithm.hexdigest()

#     return hashed_password


def hash_password(password):
    # Generate a salt and hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    return hashed_password.decode('utf-8')  # Decode bytes to string for storage




def convert_objectid_to_str(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    elif isinstance(obj, dict):
        return {key: convert_objectid_to_str(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_objectid_to_str(item) for item in obj]
    else:
        return obj


@csrf_exempt
def signup(request):
    # data = request.POST.get("email")
    data = json.loads(request.body.decode('utf-8'))
    user_data = users_collection.find_one({'email':data['email']})
    if(user_data):
        return JsonResponse({"message":"User already exists"}, status=409, safe=False)
    
    user_data = {"username": data["username"], "email": data['email'], "password" : hash_password(data["password"])}
    users_collection.insert_one(user_data)
    # print(data['username'])
    # print(result)
    return JsonResponse({'message':"Successfully Signed Up."},safe=False)


@csrf_exempt
def login(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        # print(request)
        user_data = users_collection.find_one({'email':data['email']}) 
        if(not user_data):
            return JsonResponse({'message': "user not present"},status=400)

        if( not bcrypt.checkpw(data["password"].encode('utf-8'), user_data['password'].encode('utf-8'))):
            return JsonResponse({'message': "username or password is incorrect"},status=400)
        payload = {'username':user_data['username'], 'email': user_data['email'], 'exp': datetime.utcnow() + timedelta(seconds=config("TOKEN_EXPIRATION_SECONDS", default=10, cast=int))}
        # print(payload)
        refresh_token = jwt.encode(payload, config("REFRESH_TOKEN_KEY",default="",cast=str), algorithm="HS256")
        access_token = jwt.encode({'username':user_data['username'], 'email': user_data['email'], 'exp': datetime.utcnow() + timedelta(seconds=3600)}, config("ACCESS_TOKEN_KEY"), algorithm="HS256")

        response = JsonResponse({'message':access_token})
        # Set JWT token as a cookie
        response.set_cookie('jwt', refresh_token, max_age=7 * 24 * 3600,samesite='None',secure=True)
        
        return response

    except Exception as e:
        # Handle other exceptions and return a generic error response
        return JsonResponse({'message': 'There is something wrong in the server'},status=500)

@csrf_exempt
def logout(request):
    try:
        # Remove the jwt token from the client side
        response = JsonResponse({'message':'Logged out successfully.'})
        response.delete_cookie('jwt')
        return response
    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Invalid Token'}, status=401)


@csrf_exempt
def refresh(request):
    
    if 'jwt' not in request.COOKIES:
        return JsonResponse({'message': 'Unauthorized, You are not logged in'}, status=401)

    refresh_token = request.COOKIES['jwt']
    # print(refresh_token)
    try:
        decoded = jwt.decode(refresh_token, config("REFRESH_TOKEN_KEY", default="", cast=str), algorithms=["HS256"])
        # print(decoded)
        user = users_collection.find_one({'email': decoded['email']})

        if not user:
            return JsonResponse({'message': 'Unauthorized'}, status=401)

        access_token = jwt.encode(
            {
                'username': user['username'],
                'email': user['email'],
                'exp': datetime.utcnow() + timedelta(seconds=3600)
            },
            config("ACCESS_TOKEN_KEY", default="", cast=str),
            algorithm="HS256"
            # expires_in=900  # 15 minutes in seconds
        )

        return JsonResponse({'message': access_token})

    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired'}, status=403)
    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token'}, status=403)


@csrf_exempt
def ml(request):
    data = request.POST.get("data")
    # print(data)
    loaded_model = load('./model/personality_predictor.joblib')
    result = loaded_model.predict([data])
    # print(result)
    return JsonResponse({'result':result[0]})




@csrf_exempt
def Index(request):
    return HttpResponse('<h1>This is the personality predictor backend server.</h1>')