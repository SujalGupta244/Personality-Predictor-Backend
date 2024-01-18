from django.urls import path
from . import views

urlpatterns = [
    path('', views.Index),
    path('api/',views.ml),
    path('signup/',views.signup),
    path('login/',views.login),
]