"""Password_Saver_Using_Django URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
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
from django.urls import path
from Password_Saver import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',views.index,name="register"),
    path("login/",views.login_page,name="login"),
    path("login/list/",views.list_passwords,name="list"),
    path("logout/",views.user_logout,name="logout"),
    path("add_acc_details/",views.add_acc_details,name="add_acc_details"),
    path("update/",views.update_password,name="update"),
    path("delete/",views.delete_info,name="deletedata")
]
