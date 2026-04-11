# Python modules
from typing import Any
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, OpenApiResponse

# Django REST Framework
from rest_framework.viewsets import ViewSet
from rest_framework.request import Request as DRFRequest
from rest_framework.response import Response as DRFResponse
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_405_METHOD_NOT_ALLOWED, HTTP_201_CREATED
from rest_framework.permissions import AllowAny
from rest_framework.decorators import action

# Project modules
from apps.users.models import CustomUser
from apps.users.serializers import HTTP405MethodNotAllowedSerializer, UserRegisterSerializer
from apps.abstracts.mixins import DRFResponseMixin


class CustomUserViewSet(ViewSet, DRFResponseMixin):
    """ViewSet for handling user registration and related actions."""
    permission_classes = (AllowAny,)
    @extend_schema(
        summary="User Registration",
        description="Register a new user and return JWT tokens along with user information.",
        request=UserRegisterSerializer,
        responses={
            HTTP_201_CREATED: OpenApiResponse(
                description="Successful registration returns user data along with access and refresh tokens.",
                response=UserRegisterSerializer,
            ),
            HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Bad request due to invalid input data.",
                response=UserRegisterSerializer,
            ),
            HTTP_405_METHOD_NOT_ALLOWED: OpenApiResponse(
                description="Method not allowed. You used wrong HTTP request type. Only POST can be used to reach this endpoint.",
                response=HTTP405MethodNotAllowedSerializer,
            )
        }
    )

    @action(
        methods=("POST",),
        detail=False,
        url_name="register",
        url_path="register",
        permission_classes=(AllowAny,)
    )
    def register(self, request: DRFRequest, *args: tuple[Any, ...], **kwargs: dict[str, Any]) -> DRFResponse:
        """
        Handle user registration.
        """
        serializer: UserRegisterSerializer = UserRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user: CustomUser = serializer.save()

        refresh_token: RefreshToken = RefreshToken.for_user(user)
        access_token: str = str(refresh_token.access_token)
        
        return DRFResponse(
            data={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "access": access_token,
                "refresh": str(refresh_token),
            },
            status=HTTP_201_CREATED
        )

    