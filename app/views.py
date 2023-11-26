# from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
# from django.db import connection
from joblib import load
# import pickle
from django.views.decorators.csrf import csrf_exempt
# # Create your views here.


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