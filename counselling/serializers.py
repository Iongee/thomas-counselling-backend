from django.contrib.auth import authenticate
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Session, Reflection, Round, Message, LLMResponse, Relationship, RelationshipInvitation, SessionInvitation, SessionParticipant

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from django.db import transaction
from django.utils import timezone

import requests
import json

User = get_user_model()

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        user = authenticate(
            self.context["request"],
            username=attrs["username"],
            password=attrs["password"],
        )
        if not user:
            raise serializers.ValidationError("Invalid credentials")
        attrs["user"] = user
        return attrs

class RegistrationSerializer(serializers.ModelSerializer):
    # create a user with one password field (no confirmation)
    class Meta:
        model  = User
        fields = ("username", "email", "password")
        extra_kwargs = {
            "password": {"write_only": True}   # hides password on output 
        }

    def create(self, validated_data):   
        # create_user() hashes the password for us
        return User.objects.create_user(**validated_data)

class SessionCreateSerializer(serializers.ModelSerializer):
    categories = serializers.ListField(child=serializers.CharField())
    context = serializers.CharField(required=False, allow_blank=True)
    partner_id = serializers.IntegerField(required=False, allow_null=True, help_text="ID of partner to invite")
    partner_message = serializers.CharField(required=False, allow_blank=True, help_text="Optional message for partner")

    class Meta:
        model = Session
        fields = ('categories', 'context', 'partner_id', 'partner_message')

    def validate_partner_id(self, value):
        if value is None:
            return value
            
        request = self.context.get('request')
        if not request:
            raise serializers.ValidationError("Request context required")
            
        try:
            partner = User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Partner not found")
        
        # check if user has relationship with this partner
        relationship_exists = Relationship.objects.filter(
            from_user=request.user,
            to_user=partner
        ).exists()
        
        if not relationship_exists:
            raise serializers.ValidationError("You don't have a relationship with this user")
        
        return value

    def create(self, validated_data):
        partner_id = validated_data.pop('partner_id', None)
        partner_message = validated_data.pop('partner_message', '')
        
        request = self.context['request']
        session = Session.objects.create(
            creator=request.user,
            **validated_data
        )
        
        # create session participant for creator
        SessionParticipant.objects.create(
            session=session,
            user=request.user,
            role='creator'
        )
        
        # if partner is specified, create session invitation
        if partner_id:
            partner = User.objects.get(id=partner_id)
            SessionInvitation.objects.create(
                session=session,
                from_user=request.user,
                to_user=partner,
                message=partner_message
            )
        
        return session

# Objective Generation Serializers
class ObjectiveGenerationSerializer(serializers.Serializer):
    """Serializer for generating session objectives from form data"""
    categories = serializers.ListField(child=serializers.CharField())
    context = serializers.CharField(required=False, allow_blank=True)
    partner_name = serializers.CharField(required=False, allow_blank=True)
    partner_relationship = serializers.CharField(required=False, allow_blank=True)
    
    def validate_categories(self, value):
        if not value:
            raise serializers.ValidationError("At least one category must be selected")
        return value

class ObjectiveRefinementSerializer(serializers.Serializer):
    """Serializer for refining objectives through conversation"""
    current_objectives = serializers.ListField(child=serializers.CharField())
    user_feedback = serializers.CharField()

class SessionCreateWithObjectivesSerializer(serializers.ModelSerializer):
    """Extended session creation serializer that includes objectives"""
    categories = serializers.ListField(child=serializers.CharField())
    context = serializers.CharField(required=False, allow_blank=True)
    objectives = serializers.ListField(child=serializers.CharField())
    partner_id = serializers.IntegerField(required=False, allow_null=True)
    partner_message = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = Session
        fields = ('categories', 'context', 'objectives', 'partner_id', 'partner_message')

    def validate_partner_id(self, value):
        if value is None:
            return value
            
        request = self.context.get('request')
        if not request:
            raise serializers.ValidationError("Request context required")
            
        try:
            partner = User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Partner not found")
        
        # check if user has relationship with this partner
        relationship_exists = Relationship.objects.filter(
            from_user=request.user,
            to_user=partner,
            is_active=True
        ).exists()
        
        if not relationship_exists:
            raise serializers.ValidationError("You don't have an active relationship with this user")
        
        return value

    def create(self, validated_data):
        partner_id = validated_data.pop('partner_id', None)
        partner_message = validated_data.pop('partner_message', '')
        
        request = self.context['request']
        session = Session.objects.create(
            creator=request.user,
            **validated_data
        )
        
        # create session participant for creator
        SessionParticipant.objects.create(
            session=session,
            user=request.user,
            role='creator'
        )
        
        # if partner is specified, create session invitation
        if partner_id:
            partner = User.objects.get(id=partner_id)
            SessionInvitation.objects.create(
                session=session,
                from_user=request.user,
                to_user=partner,
                message=partner_message
            )
        
        return session

class SessionReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = Session
        fields = (
            "session_uuid",
            "status",
            "categories",
            "context",
            "created_at",
            "creator",
        )
        read_only_fields = fields
    
class ReflectionCreateSerializer(serializers.ModelSerializer):
    feelings = serializers.CharField()
    hopes = serializers.CharField(write_only=True, source='expected_outcome')
    session_uuid = serializers.UUIDField(write_only=True)

    class Meta:
        model = Reflection
        fields = ('feelings', 'hopes', 'session_uuid')

    def validate_session_uuid(self, value):
        try: 
            return Session.objects.get(session_uuid=value)
        except Session.DoesNotExist:
            raise serializers.ValidationError("Invalid session UUID.")
    
    @transaction.atomic
    def create(self, validated_data):
        session = validated_data.pop('session_uuid')
        user = self.context['request'].user


        # check if reflection already exists for this user-session combination
        reflection, created = Reflection.objects.get_or_create(
            session=session,
            user=user,
            defaults=validated_data
        )
        
        # if reflection already exists, update it with new data
        if not created:
            for key, value in validated_data.items():
                setattr(reflection, key, value)
            reflection.save()

        if session.is_full() and session.status != 'active':
            session.status = 'active'
            session.save(update_fields=['status'])

            # create the first round if it doesn't exist yet
            try:
                chat_round = Round.objects.get(session=session, round_index=1)
                round_created = False
            except Round.DoesNotExist:
                chat_round = Round.objects.create(session=session, round_index=1)
                round_created = True
            except Round.MultipleObjectsReturned:
                # If multiple rounds exist, get the first one and mark as not created
                chat_round = Round.objects.filter(session=session, round_index=1).first()
                round_created = False
            # Always signal session start when session becomes active (regardless of round creation)
            # This is the moment when both users have completed reflections
            # signal that the session is ready for initial LLM response
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"{session.session_uuid}_session",
                {
                    "type": "session_started",
                    "session_uuid": str(session.session_uuid),
                },
            )

        return reflection
    
class SessionMembershipSerializer(serializers.Serializer):
    session_uuid = serializers.UUIDField()

    def validate(self, attrs):
        try:
            attrs["session"] = Session.objects.get(session_uuid=attrs["session_uuid"])
        except Session.DoesNotExist:
            raise serializers.ValidationError({"session_uuid": "Session not found."})
        return attrs

    def check_membership(self, user):
        session = self.validated_data["session"]
        
        return session.is_user_participant(user)

class SessionMessagesSerializer(serializers.Serializer):
    chat_history = serializers.SerializerMethodField()
    participants = serializers.SerializerMethodField()

    def get_chat_history(self, session):
        return session.get_all_messages()

    def get_participants(self, session):
        """Return mapping of Firebase UID to display name for all participants"""
        participants = {}

        # Add creator
        participants[session.creator.username] = session.creator.display_name

        # Add other participants
        for participant in session.participants.select_related('user'):
            participants[participant.user.username] = participant.user.display_name

        return participants

class RelationshipInvitationSerializer(serializers.ModelSerializer):
    to_email = serializers.EmailField()
    relationship_type = serializers.ChoiceField(choices=RelationshipInvitation.RELATIONSHIP_TYPES)
    message = serializers.CharField(required=False, allow_blank=True)
    
    class Meta:
        model = RelationshipInvitation
        fields = ('to_email', 'relationship_type', 'message')
    
    # can add more logic here e.g, check if user exists
    def validate_to_email(self, value):
        request = self.context.get('request')
        if request and request.user.email == value:
            raise serializers.ValidationError("You cannot invite yourself")
        return value
    
    def create(self, validated_data):
        request = self.context['request']
        
        # check if user exists and set to_user if they do
        try:
            to_user = User.objects.get(email=validated_data['to_email'])
            validated_data['to_user'] = to_user
        except User.DoesNotExist:
            to_user = None
        
        # check if relationship already exists
        if to_user:
            existing_relationship = Relationship.objects.filter(
                from_user=request.user,
                to_user=to_user
            ).exists() 
            
            if existing_relationship:
                raise serializers.ValidationError("You already have a relationship with this user")
        
        # Check if invitation already exists
        existing_invitation = RelationshipInvitation.objects.filter(
            from_user=request.user,
            to_email=validated_data['to_email'],
            status='pending'
        ).exists()
        
        if existing_invitation:
            raise serializers.ValidationError("You already have a pending invitation to this email")
        
        return RelationshipInvitation.objects.create(
            from_user=request.user,
            **validated_data
        )

class RelationshipInvitationListSerializer(serializers.ModelSerializer):
    # serializer for listing relationship invitations
    from_user = serializers.StringRelatedField()
    to_user = serializers.StringRelatedField()
    relationship_type_display = serializers.CharField(source='get_relationship_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = RelationshipInvitation
        fields = (
            'invitation_uuid', 'from_user', 'to_email', 'to_user',
            'relationship_type', 'relationship_type_display', 'message',
            'status', 'status_display', 'created_at', 'expires_at', 'is_expired'
        )
        read_only_fields = fields

class RelationshipInvitationResponseSerializer(serializers.Serializer):
    # serializer for responding to relationship invitations
    invitation_uuid = serializers.UUIDField()
    action = serializers.ChoiceField(choices=['accept', 'reject'])
    
    def validate_invitation_uuid(self, value):
        try:
            invitation = RelationshipInvitation.objects.get(invitation_uuid=value)
        except RelationshipInvitation.DoesNotExist:
            raise serializers.ValidationError("Invitation not found")
        
        if invitation.status != 'pending':
            raise serializers.ValidationError("Invitation has already been responded to")
        
        if invitation.is_expired():
            raise serializers.ValidationError("Invitation has expired")
        
        request = self.context.get('request')
        if request and request.user.email != invitation.to_email:
            raise serializers.ValidationError("You are not authorized to respond to this invitation")
        
        # set to_user if not already set (for users who signed up after invitation was sent)
        if not invitation.to_user and request:
            invitation.to_user = request.user
            invitation.save()
        
        return value

class RelationshipSerializer(serializers.ModelSerializer):
    from_user = serializers.StringRelatedField()
    to_user = serializers.StringRelatedField()
    to_user_email = serializers.EmailField(source='to_user.email', read_only=True)
    relationship_type_display = serializers.CharField(source='get_relationship_type_display', read_only=True)
    
    class Meta:
        model = Relationship
        fields = (
            'id', 'from_user', 'to_user', 'to_user_email',
            'relationship_type', 'relationship_type_display',
            'context', 'notes', 'created_at', 'updated_at'
        )
        read_only_fields = fields

class UserNetworkSerializer(serializers.Serializer):
    relationships = RelationshipSerializer(many=True, read_only=True)
    sent_invitations = RelationshipInvitationListSerializer(many=True, read_only=True)
    received_invitations = RelationshipInvitationListSerializer(many=True, read_only=True)

class RelationshipUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Relationship
        fields = ('relationship_type', 'context', 'notes')
    
    def update(self, instance, validated_data):
        instance.relationship_type = validated_data.get('relationship_type', instance.relationship_type)
        instance.context = validated_data.get('context', instance.context)
        instance.notes = validated_data.get('notes', instance.notes)
        instance.save()
        return instance

class SessionInvitationSerializer(serializers.ModelSerializer):
    to_user_id = serializers.IntegerField()
    message = serializers.CharField(required=False, allow_blank=True)
    
    class Meta:
        model = SessionInvitation
        fields = ('to_user_id', 'message')
    
    def validate_to_user_id(self, value):
        request = self.context.get('request')
        if not request:
            raise serializers.ValidationError("Request context required")
            
        try:
            to_user = User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        
        # Check if user has relationship with this person
        relationship_exists = Relationship.objects.filter(
            from_user=request.user,
            to_user=to_user
        ).exists()
        
        if not relationship_exists:
            raise serializers.ValidationError("You don't have a relationship with this user")
        
        return value

class SessionInvitationListSerializer(serializers.ModelSerializer):
    from_user = serializers.StringRelatedField()
    to_user = serializers.StringRelatedField()
    session_categories = serializers.SerializerMethodField()
    session_context = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    
    def get_session_categories(self, obj):
        return obj.session.categories
    
    def get_session_context(self, obj):
        return obj.session.context
    
    class Meta:
        model = SessionInvitation
        fields = (
            'invitation_uuid', 'from_user', 'to_user', 'message',
            'session_categories', 'session_context', 'status', 'status_display',
            'created_at', 'expires_at', 'is_expired'
        )
        read_only_fields = fields

class SessionInvitationResponseSerializer(serializers.Serializer):
    invitation_uuid = serializers.UUIDField()
    action = serializers.ChoiceField(choices=['accept', 'reject'])
    
    def validate_invitation_uuid(self, value):
        try:
            invitation = SessionInvitation.objects.get(invitation_uuid=value)
        except SessionInvitation.DoesNotExist:
            raise serializers.ValidationError("Session invitation not found")
        
        if invitation.status != 'pending':
            raise serializers.ValidationError("Session invitation has already been responded to")
        
        if invitation.is_expired():
            raise serializers.ValidationError("Session invitation has expired")
        
        request = self.context.get('request')
        if request and request.user != invitation.to_user:
            raise serializers.ValidationError("You are not authorized to respond to this invitation")
        
        return value