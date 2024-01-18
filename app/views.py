# from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
# from django.db import connection
from joblib import load
# import pickle
from django.views.decorators.csrf import csrf_exempt
# # Create your views here.
import json

from .models import users_collection

import bcrypt
# import hashlib


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


@csrf_exempt
def signup(request):
    # data = request.POST.get("email")
    data = json.loads(request.body.decode('utf-8'))
    user_data = {"username": data["username"], "email": data['email'], "password" : hash_password(data["password"])}
    users_collection.insert_one(user_data)
    # print(data['username'])
    # print(result)
    return JsonResponse({'message':"Successfully Signed Up."},safe=False)


@csrf_exempt
def login(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        user_data = users_collection.find_one({'email':data['email']}) 
        # print(hash_password(data["password"]),user_data)
        if(user_data):
            return JsonResponse({'message':"Successfully Logged In."},safe=False)
        else:
            # Handle specific exception and return an error response
            return JsonResponse({'error': "username or password is incorrect"},status=400)
    except Exception as e:
        # Handle other exceptions and return a generic error response
        return JsonResponse({'error': 'An unexpected error occurred','message':e},status=500)

@csrf_exempt
def logout(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        user_data = users_collection.find_one({'email':data['email']}) 
        # print(hash_password(data["password"]),user_data)
        if(user_data):
            return JsonResponse({'message':"Successfully Logged Out."},safe=False)
        
    except Exception as e:
        # Handle other exceptions and return a generic error response
        return JsonResponse({'error': 'An unexpected error occurred','message':e},status=500)



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