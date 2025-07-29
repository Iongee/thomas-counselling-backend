from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ['email', 'username', 'display_name', 'is_staff']
    
    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('display_name',)}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {'fields': ('display_name',)}),
    )

admin.site.register(User, CustomUserAdmin)