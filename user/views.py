from django.contrib.auth import get_user_model
from django.shortcuts import render
from rest_framework.request import Request
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from .serializers import UserSerializer
# Create your views here.
User = get_user_model()


class RegisterView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        try:
            data = request.data

            name = data['name']
            email = data['email']
            email = email.lower()
            password = data['password']
            re_password = data['re_password']
            is_realtor = data['is_realtor']

            if is_realtor == 'True':
                is_realtor = True
            else:
                is_realtor = False

            if password == re_password:
                if len(password) >= 8:
                    if not User.objects.filter(email=email).exists():
                        if not is_realtor:
                            User.objects.create_user(
                                name=name, email=email, password=password)
                            return Response(
                                {'success': 'User created successfully'}, status=status.HTTP_201_CREATED
                            )
                        else:
                            User.objects.create_realtor(
                                name=name, email=email, password=password)

                            return Response(
                                {'success': 'Realtor account created successfully'}, status=status.HTTP_201_CREATED
                            )
                    else:
                        return Response({'error': 'User with this email already exists'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({'error': 'Passwords must be atleast 8 characters'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response(
                {'error': 'Something went wrong when registering an account'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RetrieveUserView(APIView):
    def get(self, request, format=None):
        try:
            user = request.user
            user = UserSerializer(user)

            return Response({
                'user': user.data
            }, status=status.HTTP_200_OK)
        except:
            return Response(
                {'error': 'Something went wrong while retrieving user details'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LoginView(TokenObtainPairView):
    def post(self, request: Request, *args, **kwargs):
        email = request.data['email']
        response = super().post(request, *args, **kwargs)

        if (response.status_code == status.HTTP_200_OK and User.objects.filter(email=email).exists()):
            user = User.objects.filter(email=email).get(email=email)
            print(user)
            response.data['user'] = {
                'name': user.name,
                'email': user.email,
                'is_realtor': user.is_realtor,
                'is_active': user.is_active,
            }

        return response
