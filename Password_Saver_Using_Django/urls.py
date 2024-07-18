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
from django.urls import path,re_path
from Password_Saver import views
from django.contrib.auth import views as auth_views
from django.conf.urls.static import static
from django.conf import settings


urlpatterns = [
    path('admin/', admin.site.urls),
    path('',views.index,name="register"),
     path("verifyemail",views.verify_otp,name="verifyotp"),
    path("login/",views.login_page,name="login"),
    path("login/list/",views.list_passwords,name="list"),
    path("logout/",views.user_logout,name="logout"),
    path("add_acc_details/",views.add_acc_details,name="add_acc_details"),
    path("add/",views.add_acc,name="add_account"),
    path("update/",views.update_password,name="update"),
    path("delete/",views.delete_info,name="deletedata"),
     path("delete/",views.delete_info,name="deletedata"),
    path("password-reset/", auth_views.PasswordResetView.as_view(template_name = "users_password_reset/reset_password.html"), name = "password_reset"),
    path("password_reset/done/",auth_views.PasswordResetDoneView.as_view(template_name = "users_password_reset/password_reset_done.html"),name="password_reset_done"),
    path("password_reset_confirm/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(template_name = "users_password_reset/password_reset_confirm.html"),
          name = "password_reset_confirm"),
    path("password_reset_complete/",
auth_views.PasswordResetCompleteView.as_view(template_name = "users_password_reset/password_reset_complete.html"),
    name = "password_reset_complete"),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

