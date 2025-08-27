"""
URL configuration for secure_auth project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from accounts.forms import LockedAccountAuthenticationForm

urlpatterns = [
    path('admin/', admin.site.urls),
    # Login personnalisé
    path('accounts/login/', auth_views.LoginView.as_view(authentication_form=LockedAccountAuthenticationForm), name='login'),
    # Inclure les autres URLs d'authentification (logout, password_change, etc.)
    path('accounts/', include('django.contrib.auth.urls')),
]
