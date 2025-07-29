from django.contrib import admin
from counselling.models import (Session, SessionParticipant, Round, Message, LLMResponse, 
                               Reflection, Relationship, RelationshipInvitation, SessionInvitation,
                               ObjectiveRoom, Reflection, Relationship, RelationshipInvitation, SessionInvitation, SessionSummaryResponse)

# Register your models here.
admin.site.register(Session)
admin.site.register(SessionParticipant)
admin.site.register(Round)
admin.site.register(Message)
admin.site.register(LLMResponse)
admin.site.register(Reflection)

@admin.register(Relationship)
class RelationshipAdmin(admin.ModelAdmin):
    list_display = ('from_user', 'to_user', 'relationship_type', 'is_active', 'created_at')
    list_filter = ('relationship_type', 'is_active', 'created_at')
    # Search by display_name and email, not the internal UID (username)
    search_fields = ('from_user__display_name', 'to_user__display_name', 'from_user__email', 'to_user__email')
    readonly_fields = ('created_at',)

@admin.register(RelationshipInvitation)
class RelationshipInvitationAdmin(admin.ModelAdmin):
    list_display = ('from_user', 'to_email', 'to_user', 'relationship_type', 'status', 'created_at', 'expires_at')
    list_filter = ('relationship_type', 'status', 'created_at')
    # Search by display_name and email
    search_fields = ('from_user__display_name', 'to_email', 'to_user__display_name')
    readonly_fields = ('invitation_uuid', 'created_at', 'responded_at')
    
    def get_readonly_fields(self, request, obj=None):
        if obj:
            return self.readonly_fields + ('from_user', 'to_email')
        return self.readonly_fields

@admin.register(SessionInvitation)
class SessionInvitationAdmin(admin.ModelAdmin):
    list_display = ('from_user', 'to_user', 'session', 'status', 'created_at', 'expires_at')
    list_filter = ('status', 'created_at')
    # Search by display_name
    search_fields = ('from_user__display_name', 'to_user__display_name', 'session__session_uuid')
    readonly_fields = ('invitation_uuid', 'created_at', 'responded_at')
    
    def get_readonly_fields(self, request, obj=None):
        if obj:
            return self.readonly_fields + ('from_user', 'to_user', 'session')
        return self.readonly_fields

@admin.register(ObjectiveRoom)
class ObjectiveRoomAdmin(admin.ModelAdmin):
    list_display = ('session', 'objective_index', 'status', 'created_at', 'completed_at')
    list_filter = ('status', 'created_at')
    search_fields = ('session__session_uuid', 'objective_text')
    readonly_fields = ('created_at', 'completed_at')

@admin.register(SessionSummaryResponse)
class SessionSummaryResponseAdmin(admin.ModelAdmin):
    list_display = ('session', 'user', 'submitted_at')
    list_filter = ('submitted_at',)
    search_fields = ('user__display_name', 'session__session_uuid')
    readonly_fields = ('submitted_at',)
