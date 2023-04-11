from django.db import models
#from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth.models  import User 
# Create your models here.

class AccountInfo(models.Model):
    account_name = models.CharField("Account Name ",max_length=200)
    user_name = models.CharField("User Name ",max_length=200)
    password = models.CharField("Password ",max_length=200)
    user = models.ForeignKey(User,on_delete=models.CASCADE,related_name="acc_details")