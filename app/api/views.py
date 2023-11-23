from rest_framework.viewsets import ModelViewSet
from ..models import App
from .serializers import AppSerializer

class AppViewSet(ModelViewSet):
    queryset = App.objects.all()
    serializer_class = AppSerializer

# class AppView():
#     pass    