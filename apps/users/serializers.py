from typing import Any

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from apps.users.models import CustomUser


class HTTP405MethodNotAllowedSerializer(serializers.Serializer):
	detail = serializers.CharField(read_only=True)


class UserRegisterSerializer(serializers.ModelSerializer):
	password = serializers.CharField(write_only=True, required=True)
	password2 = serializers.CharField(write_only=True, required=True)

	class Meta:
		model = CustomUser
		fields = (
			'id',
			'email',
			'username',
			'first_name',
			'last_name',
			'password',
			'password2',
		)
		read_only_fields = ('id',)

	def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
		if attrs.get('password') != attrs.get('password2'):
			raise serializers.ValidationError({'password': "Passwords do not match."})

		try:
			validate_password(password=attrs.get('password'))
		except DjangoValidationError as exc:
			raise serializers.ValidationError({'password': list(exc.messages)})

		return attrs

	def create(self, validated_data: dict[str, Any]) -> CustomUser:
		validated_data.pop('password2', None)
		password = validated_data.pop('password')
		user: CustomUser = CustomUser.objects.create_user(
			email=validated_data.get('email'),
			username=validated_data.get('username'),
			password=password,
			**{k: v for k, v in validated_data.items() if k in ('first_name', 'last_name')}
		)
		return user

