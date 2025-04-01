#imports
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("download/<str:filename>", views.download_file, name = "download_file"),
]


urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)