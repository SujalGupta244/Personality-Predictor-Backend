from rest_framework.serializers import ModelSerializer
from ..models import App


class AppSerializer(ModelSerializer):
    class Meta:
        model = App
        # fields = '__all__'
        fields = ('id','title', 'body')
