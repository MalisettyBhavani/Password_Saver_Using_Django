from django.shortcuts import render,get_object_or_404
from django.urls import reverse,reverse_lazy
from Password_Saver.forms import RegistrationForm,LoginForm,AccountInfoForm,UpdatePasswordForm
from django.contrib.auth import authenticate,login,logout
from django.http import HttpResponse,HttpResponseRedirect,JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from Password_Saver.models import AccountInfo
from django.contrib.auth.models import User
from Password_Saver.encrypt_decrypt import encrypt,decrypt
from django.views.decorators.csrf import requires_csrf_token,csrf_exempt
from bootstrap_modal_forms.generic import BSModalCreateView,BSModalDeleteView,BSModalUpdateView,BSModalDeleteView
# Create your views here.
def index(request):
    reg_form = RegistrationForm()
    registered = False
    if request.method =="POST":
        reg_form = RegistrationForm(request.POST)
        if reg_form.is_valid():
            reg_form = reg_form.save()
            reg_form.set_password(reg_form.password)
            reg_form.save() 
            registered = True
    return render(request,'registration.html',{'reg_form':reg_form,'registered':registered})

def login_page(request):
    login_form = LoginForm()
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(username=username,password=password)
        if user:
            if user.is_active:
                login(request,user)
                return HttpResponseRedirect("list")
            else:
                return HttpResponse("User is Inactive!")
        else:
            return HttpResponse("Invalid Credentials!")
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

def update_password(request,id):
    update_obj=get_object_or_404(AccountInfo,id=id)
    if(request.method=="POST"):
        modify_password = UpdatePasswordForm(request.POST,instance=update_obj)
        if modify_password.is_valid():
            modify_password.save()
            return HttpResponseRedirect(reverse("list"))
    else:
        modify_password = UpdatePasswordForm()
    return render(request,'update_password.html',{'modify_password':modify_password})

def delete_info(request,id):
    delete_obj=get_object_or_404(AccountInfo,id=id)
    if(request.method=="POST"):
        delete_obj.delete()
        return HttpResponseRedirect(reverse("list"))
    else:
        return render(request,"delete_acc.html",{})
    
@csrf_exempt 
def get_decrypted_data(request):
    if  request.method =="POST":
        password = request.POST
        decrypted_password = decrypt(password['decrypt_password'])
        return JsonResponse({"instance": decrypted_password}, status=200)
    


    