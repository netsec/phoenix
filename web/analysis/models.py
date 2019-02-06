import datetime
from django.db import models, transaction
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from django.db.models.signals import post_save


class UsageLimits(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    allowed_per_day = models.IntegerField(default=25)
    used_today = models.IntegerField(default=0)
    last_date_checked = models.DateField(auto_now=True)

    @classmethod
    def get_credit(cls, user):
        with transaction.atomic():
            limits = (cls.objects.select_for_update().get_or_create(user=user)[0])
            if datetime.datetime.today().date() > limits.last_date_checked:
                limits.used_today = 0
            return limits.allowed_per_day - limits.used_today

    @classmethod
    def take_credit(cls, user):
        with transaction.atomic():
            limits = (cls.objects.select_for_update().get_or_create(user=user)[0])
            if datetime.datetime.today().date() > limits.last_date_checked:
                limits.used_today = 0
            new_credits = limits.allowed_per_day - limits.used_today
            if new_credits > 0:
                limits.used_today += 1
                limits.save()
                return True
            return False

# Define an inline admin descriptor for Employee model
# which acts a bit like a singleton
class UsageLimitsInline(admin.StackedInline):
    model = UsageLimits
    can_delete = False
    verbose_name_plural = 'Usage'


# Define a new User admin
class UserAdmin(BaseUserAdmin):
    inlines = (UsageLimitsInline, )


# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)


def create_profile(sender, **kw):
    user = kw["instance"]
    if kw["created"]:
        profile = UsageLimits(user=user)
        profile.save()


post_save.connect(create_profile, sender=User, dispatch_uid="users-profilecreation-signal")


def get_usage_limits(user):
    limits, existed = UsageLimits.objects.get_or_create(user=user)
    # if "usagelimits" in user:
    #     limits = user.usagelimits
    # else:
    #     limits = UsageLimits(user=user)
    #     limits.allowed_per_day = 50
    if datetime.datetime.today().date() > limits.last_date_checked:
        limits.used_today = 0
        limits.save()
    return limits



