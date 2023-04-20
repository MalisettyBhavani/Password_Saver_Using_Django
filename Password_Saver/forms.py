from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from Password_Saver.models import AccountInfo
from django.forms import ValidationError
from Password_Saver.encrypt_decrypt import encrypt


class RegistrationForm(UserCreationForm):
    username = forms.CharField(label="User name",max_length=200,widget=forms.TextInput(attrs={"placeholder":"Username","class":"form-control"}))
    email = forms.EmailField(label="Email ",widget=forms.TextInput(attrs={"placeholder":"Email","class":"form-control"}))
    password1 = forms.CharField(label="Password ",widget= forms.PasswordInput(attrs={"placeholder":"Password","class":"form-control"}))
    password2 = forms.CharField(label="Confirm Password",widget=forms.PasswordInput(attrs={"placeholder":"Confirm Password","class":"form-control"}))
    
    class Meta:
        model = User
        fields = ('username','email','password1','password2')
    def __str__(self):
        return self.username

class LoginForm(forms.ModelForm):
    username = forms.CharField(max_length=200,widget=forms.TextInput(attrs={"placeholder":"Username","class":"form-control"}))
    password = forms.CharField(label="Password",widget=forms.PasswordInput(attrs={"placeholder":"Password","class":"form-control"}))
    class Meta:
        model = User
        fields = ('username','password')

class AccountInfoForm(forms.ModelForm):
    password = forms.CharField(label="Password",widget=forms.PasswordInput())
    class Meta:
        model = AccountInfo
        fields = ('account_name','user_name','password')

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(AccountInfoForm, self).__init__(*args, **kwargs)

    def clean_password(self):
        if(self.is_valid()):
            encrypted_password=encrypt(self.cleaned_data["password"])
            self.cleaned_data["password"]=encrypted_password
        return self.cleaned_data["password"]
    
    def clean(self):
        if(self.is_valid()):
            data = AccountInfo.objects.filter(user__id=self.user.id).values()
            l=list(data)
            form_acc_name=self.cleaned_data["account_name"]
            for i in l:
                acc_name = i.get("account_name")
                if acc_name.strip().lower()==form_acc_name.strip().lower():
                    raise ValidationError("This account info already exists!")
                    
                

