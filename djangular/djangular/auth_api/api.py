import logging
from django.http import HttpResponse

from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator

from rest_framework import status, views
from rest_framework.response import Response

from .serializers import UserSerializer

logger = logging.getLogger(__name__)

class LoginView(views.APIView):

    @method_decorator(csrf_protect)
    def post(self, request):

        logger.error("LOGIN POST!!")

        user = authenticate(
            username=request.data.get("username"),
            password=request.data.get("password"))

        if user is None or not user.is_active:
            return Response({
                'status': 'Unauthorized',
                'message': 'Userename or password incorrect'
        }, status=status.HTTP_401_UNAUTHORIZED)

        login(request, user)
        return Response(UserSerializer(user).data)

class LogoutView(views.APIView):

    def get(self, request):

        logger.error("LOGOUT GET!!")

        logout(request)
        return Response({}, status=status.HTTP_204_NO_CONTENT)