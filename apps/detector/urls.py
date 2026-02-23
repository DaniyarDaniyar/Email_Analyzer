# Django modules
from django.urls import include, path

# Django Rest Framework modules
from rest_framework.routers import DefaultRouter

# Project modules
from apps.detector.views import DetectorViewSet


router: DefaultRouter = DefaultRouter(
    trailing_slash=False
)

router.register(
    prefix="",
    viewset=DetectorViewSet,
    basename="detector",
)

urlpatterns = [
    path("", include(router.urls)),
]