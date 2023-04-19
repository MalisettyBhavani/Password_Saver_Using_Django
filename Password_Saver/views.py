from django.shortcuts import render,get_object_or_404
from django.urls import reverse,reverse_lazy
from Password_Saver.forms import RegistrationForm,LoginForm,AccountInfoForm,UpdatePasswordForm
from django.contrib.auth import authenticate,login,logout
from django.http import HttpResponse,HttpResponseRedirect,JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from Password_Saver.models import AccountInfo
from django.contrib.auth.models import User
from Password_Saver.encrypt_decrypt import decrypt
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
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
            print(reg_form.errors)
            print(reg_form.errors.values())
            print(list(reg_form.errors.values()))

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
            print(login_form.errors)
            messages.error(request,"You entered an incorrect username or password")
            print(messages)
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
        print(add_details)
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

def updatetest(request):
    return HttpResponse("hellooo")

def delete_info(request,id):
    delete_obj=get_object_or_404(AccountInfo,id=id)
    if(request.method=="POST"):
        delete_obj.delete()
        return HttpResponseRedirect(reverse("list"))
    else:
        return render(request,"delete_acc.html",{})
    
def delete_infomodal(request):
    if request.method=="POST":
        id = request.POST.get("id")
        current_user = request.user.id
        current_user_objects = AccountInfo.objects.filter(user_id=current_user,id=id).values()
        if len(current_user_objects)!=0:
            delete_obj=get_object_or_404(AccountInfo,id=id)
            delete_obj.delete()
    else:
        print("get")
        print(request)

    return HttpResponseRedirect(reverse("list"))
    
    
@csrf_exempt 
def get_decrypted_data(request):
    if  request.method =="POST":
        password = request.POST
        decrypted_password = decrypt(password['decrypt_password'])
        return JsonResponse({"instance": decrypted_password}, status=200)
    


    