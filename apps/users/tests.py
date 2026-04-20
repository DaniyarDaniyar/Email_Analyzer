# Django modules
from django.test import TestCase

# Project modules
from apps.users.serializers import UserRegisterSerializer


class UserRegisterSerializerTests(TestCase):
	def test_passwords_must_match(self):
		serializer = UserRegisterSerializer(
			data={
				"email": "alice@example.com",
				"username": "alice",
				"password": "StrongPass123!",
				"password2": "Mismatch123!",
			}
		)
		self.assertFalse(serializer.is_valid())
		self.assertIn("password", serializer.errors)

	def test_register_creates_user(self):
		serializer = UserRegisterSerializer(
			data={
				"email": "bob@example.com",
				"username": "bob",
				"password": "StrongPass123!",
				"password2": "StrongPass123!",
			}
		)
		self.assertTrue(serializer.is_valid(), serializer.errors)
		user = serializer.save()
		self.assertEqual(user.email, "bob@example.com")
		self.assertTrue(user.check_password("StrongPass123!"))
