from django.shortcuts import render,get_object_or_404
from django.urls import reverse
from Password_Saver.forms import RegistrationForm,LoginForm,AccountInfoForm
from django.contrib.auth import authenticate,login,logout
from django.http import HttpResponse,HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from Password_Saver.models import AccountInfo
from Password_Saver.encrypt_decrypt import encrypt,decrypt
from django.contrib import messages
import time
# Create your views here.
def index(request):
    registered = False
    reg_form = RegistrationForm()
    error=None
    if request.method =="POST":
        reg_form = RegistrationForm(request.POST)
        if reg_form.is_valid():
            reg = reg_form.save()                   
            reg.set_password(reg.password)          
            reg_form.save()                         
            registered = True
            reg_form = RegistrationForm()
        else:
            error=list(reg_form.errors.values())[0]
    return render(request,'registration.html',{'reg_form':reg_form,'registered':registered,'error':error})    

def login_page(request):
    login_form = LoginForm()
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request,username=username,password=password)
        if user:
            if user.is_active:
                login(request,user)
                return HttpResponseRedirect("list")
            else:
                return HttpResponse("User is Inactive!")
        else:
            messages.error(request,"You entered an incorrect username or password")
    return render(request,'login.html',{'login_form':login_form})

@login_required
def list_passwords(request): 
    if request.user.is_authenticated:                                  
        details=AccountInfo.objects.values().filter(user__username=request.user)
        x=details#list of dictionaries
        for i in x:
            try:
                i["password"] = decrypt(i["password"])
            except:
                pass
        return render(request,'home.html',{'details':details})
    
    
@login_required
def user_logout(request):
    logout(request)
    return HttpResponseRedirect(reverse("login"))

@login_required
def add_acc_details(request):
    if request.method=="POST":
        add_details = AccountInfoForm(request.user,request.POST)
        if add_details.is_valid():
            add_details.save(commit=False)
            add_details.instance.user = request.user
            add_details.save()
            return HttpResponseRedirect(reverse("list"))
    else:
        add_details = AccountInfoForm(request.user)
    return render(request,'add_account.html',{'add_account':add_details})

@login_required
def add_acc(request):
    if request.method=="POST":
        add_details = AccountInfoForm(request.user,request.POST)
        if add_details.is_valid():
            add_details.save(commit=False)
            add_details.instance.user = request.user
            add_details.save()
            messages.success(request,"Account details are added successfully!")
            return HttpResponseRedirect(reverse("list"))
        else:
            messages.warning(request,"This account info already exists!")
            #print(messages.get_messages(request))###this is getting printed in console.log
            return HttpResponseRedirect(reverse("list"))


def update_password(request):
    if request.method == "POST":
        password = request.POST.get("password")
        encrypted_password = encrypt(password)
        id = request.POST.get("id")
        update_data_obj=AccountInfo.objects.filter(user_id=request.user.id,id=id).values().update(password=encrypted_password)
        messages.success(request,"Password updated successfully")
        return HttpResponseRedirect(reverse("list"))

def delete_info(request):
    if request.method=="POST":
        id = request.POST.get("id")
        current_user = request.user.id
        current_user_objects = AccountInfo.objects.filter(user_id=current_user,id=id).values()
        if len(current_user_objects)!=0:
            delete_obj=get_object_or_404(AccountInfo,id=id)
            delete_obj.delete()
        messages.success(request,"An entry has been successfully deleted")
        return HttpResponseRedirect(reverse("list"))
    


    