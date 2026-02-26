from typing import Sequence

from django import forms
from django.contrib.admin import register
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField

from unfold.admin import ModelAdmin

from apps.users.models import CustomUser


class CustomUserCreationForm(forms.ModelForm):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    password1 = forms.CharField(label="Password", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Password confirmation", widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ("email", "username", "first_name", "last_name")

    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("The two password fields didn't match.")
        return password2

    def save(self, commit: bool = True):
        # Save the provided password in hashed format
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class CustomUserChangeForm(forms.ModelForm):
    """A form for updating users. Replaces the password field with
    admin's disabled password hash display field."""

    password = ReadOnlyPasswordHashField()

    class Meta:
        model = CustomUser
        fields = (
            "email",
            "username",
            "first_name",
            "last_name",
            "password",
            "is_active",
            "is_staff",
        )

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        # This is done here so that the password hash isn't validated again.
        return self.initial.get("password")


@register(CustomUser)
class CustomUserAdmin(DjangoUserAdmin, ModelAdmin):
    """Admin interface for the CustomUser model."""

    form = CustomUserChangeForm
    add_form = CustomUserCreationForm

    list_display: Sequence[str] = ("email", "username", "is_staff", "is_active")
    search_fields: Sequence[str] = ("email", "username")
    list_filter: Sequence[str] = ("is_staff", "is_active")
    ordering: Sequence[str] = ("email",)

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal info", {"fields": ("username", "first_name", "last_name")}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Important dates", {"fields": ("last_login",)}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "username", "password1", "password2"),
            },
        ),
    )

    readonly_fields: Sequence[str] = ("last_login",)
    filter_horizontal: Sequence[str] = ("groups", "user_permissions")