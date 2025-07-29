from django.db import models
from itertools import chain
from operator import itemgetter

import uuid
from django.db.models import Prefetch, Max
from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist
from datetime import timedelta

class Session(models.Model):
    creator = models.ForeignKey(
        'users.User',
        related_name='created_sessions',
        on_delete=models.CASCADE
    )
    session_uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('rejected', 'Rejected')
    ]
    status = models.CharField(max_length=20,choices=STATUS_CHOICES,default='pending')

    categories = models.JSONField(default=list)
    context = models.TextField(blank=True)
    objectives = models.JSONField(default=list, help_text="AI-generated objectives for the session")
    current_objective_index = models.PositiveIntegerField(default=0, help_text="Index of the current active objective")

    capacity = models.PositiveSmallIntegerField(default=2)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Session completion fields
    end_session_votes = models.JSONField(default=dict, blank=True, help_text="Tracks votes from participants to end the session")
    end_session_vote_active = models.BooleanField(default=False, help_text="Whether there's an active vote to end the session")
    end_session_vote_initiated_by = models.CharField(max_length=150, blank=True, help_text="Username of the person who initiated the end session vote")
    final_summary = models.TextField(blank=True, help_text="AI-generated final summary of the session")
    summary_generated = models.BooleanField(default=False, help_text="Whether the final summary has been generated")

    # Soft delete functionality
    hidden_by_creator = models.BooleanField(default=False, help_text="Whether the session creator has hidden this session")
    hidden_by_invitee = models.BooleanField(default=False, help_text="Whether the invitee has hidden this session")

    def get_current_objective_room(self):
        """Get the current active objective room"""
        if not self.objectives:
            return None
        return self.objective_rooms.filter(objective_index=self.current_objective_index).first()

    def advance_to_next_objective(self):
        """Move to the next objective if available"""
        if self.current_objective_index + 1 < len(self.objectives):
            self.current_objective_index += 1
            self.save()
            # Create the next objective room
            ObjectiveRoom.objects.create(
                session=self,
                objective_index=self.current_objective_index,
                objective_text=self.objectives[self.current_objective_index]
            )
            return True
        else:
            self.status = 'completed'
            self.save()
            return False

    def reset_end_session_vote(self):
        """Reset the end session voting state"""
        self.end_session_votes = {}
        self.end_session_vote_initiated_by = ""
        self.end_session_vote_active = False
        self.save()

    def is_on_last_objective(self):
        """Check if session is on the last objective"""
        return self.current_objective_index >= len(self.objectives) - 1

    def is_full(self):
        return self.reflections.count() >= self.capacity

    def is_read_only(self):
        """Check if session is read-only (completed or rejected)"""
        return self.status in ['completed', 'rejected']
    
    def get_current_round(self):
        last_round = (
            self.rounds
            .select_related("llm_response")
            .order_by('-round_index')
            .first()
        )

        if last_round is None:
            last_round = Round.objects.create(
                session=self,
                round_index=1
            )
        else:
            try:
                _ = last_round.llm_response
                answered = True
            except ObjectDoesNotExist:
                answered = False
            
            if answered:
                next_idx = self.rounds.aggregate(
                    max_idx=models.Max('round_index')
                )['max_idx'] or 0
                
                last_round = Round.objects.create(
                    session=self,
                    round_index=next_idx + 1
                )
        
        return last_round
    
    def get_turn_state_for_user(self, user):
        """Calculate the current turn state for the session and user."""
        current_round = self.get_current_round()
        messages_in_round = current_round.messages.select_related('sender').order_by('sent_at')
        
        user_has_spoken = messages_in_round.filter(sender=user).exists()
        llm_has_responded = hasattr(current_round, 'llm_response')
        
        participants = self.participants.select_related('user')
        participant_usernames = [p.user.display_name for p in participants]
        messages_by_user = {msg.sender.display_name for msg in messages_in_round}
        
        waiting_for = []
        if not user_has_spoken:
            can_send = True
            status = "your_turn"
        else:
            can_send = False
            for username in participant_usernames:
                if username != user.display_name and username not in messages_by_user:
                    waiting_for.append(username)
            
            if waiting_for:
                status = "waiting_for_partner"
                
            elif not llm_has_responded:
                status = "waiting_for_ai"
                waiting_for.append("AI Counselor")
            else:
                status = "ready_for_new_round"
        
        return {
            'can_send': can_send,
            'status': status,
            'waiting_for': waiting_for,
            'round_index': current_round.round_index,
            'messages_in_round': messages_in_round.count()
        }
    
    def is_user_participant(self, user):
        """Check if a user is a participant in this session."""
        return (
            self.participants.filter(user=user).exists() or
            self.creator == user
        )

    def is_hidden_by_user(self, user):
        """Check if this session is hidden by the specified user."""
        if self.creator == user:
            return self.hidden_by_creator
        elif self.participants.filter(user=user).exists():
            return self.hidden_by_invitee
        return False

    def hide_for_user(self, user):
        """Hide this session for the specified user (soft delete)."""
        if self.creator == user:
            self.hidden_by_creator = True
        elif self.participants.filter(user=user).exists():
            self.hidden_by_invitee = True
        else:
            return False  # User is not a participant
        self.save()
        return True

    def unhide_for_user(self, user):
        """Unhide this session for the specified user."""
        if self.creator == user:
            self.hidden_by_creator = False
        elif self.participants.filter(user=user).exists():
            self.hidden_by_invitee = False
        else:
            return False  # User is not a participant
        self.save()
        return True

    def should_be_hard_deleted(self):
        """Check if this session should be permanently deleted (both participants have soft-deleted it)."""
        return self.hidden_by_creator and self.hidden_by_invitee
    
    def get_all_messages(self):
        rounds = self.rounds.prefetch_related(
            Prefetch(
                'messages',
                queryset=Message.objects.select_related('sender'),
            )
        )

        human = (
            {
                'content': m.content,
                'created_at': m.sent_at.isoformat(),
                'sender':   m.sender.display_name,
            }
            for rnd in rounds
            for m in rnd.messages.all()
        )

        llm = (
            {
                'content': r.content,
                'created_at': r.inferenced_at.isoformat(),
                'sender': 'llm',
            }
            for r in LLMResponse.objects.filter(chat_round__session=self)
        )

        chat = list(chain(human, llm))
        chat.sort(key=itemgetter('created_at'))
        return chat
        

    def __str__(self):
        return f"Session {self.session_uuid}"

class Relationship(models.Model):
    RELATIONSHIP_TYPES = [
        ('family', 'Family'),
        ('friend', 'Friend'),
        ('significant_other', 'Significant Other'),
        ('colleague', 'Colleague'),
        ('other', 'Other'),
    ]

    from_user = models.ForeignKey(
        'users.User',
        related_name='relationships_created',
        on_delete=models.CASCADE
    )
    to_user = models.ForeignKey(
        'users.User',
        related_name='relationships_received',
        on_delete=models.CASCADE
    )
    relationship_type = models.CharField(
        max_length=20,
        choices=RELATIONSHIP_TYPES
    )
    context = models.TextField(
        blank=True,
        help_text="Describe the context of your relationship"
    )
    notes = models.TextField(
        blank=True,
        help_text="Additional notes about this relationship"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['from_user', 'to_user'],
                name='unique_relationship'
            )
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.from_user.display_name} -> {self.to_user.display_name} ({self.get_relationship_type_display()})"

class RelationshipInvitation(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
        ('expired', 'Expired'),
    ]
    
    RELATIONSHIP_TYPES = [
        ('family', 'Family'),
        ('friend', 'Friend'),
        ('significant_other', 'Significant Other'),
        ('colleague', 'Colleague'),
        ('other', 'Other'),
    ]
    
    invitation_uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    from_user = models.ForeignKey(
        'users.User',
        related_name='sent_relationship_invitations',
        on_delete=models.CASCADE
    )
    to_email = models.EmailField()
    to_user = models.ForeignKey(
        'users.User',
        related_name='received_relationship_invitations',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    relationship_type = models.CharField(
        max_length=20,
        choices=RELATIONSHIP_TYPES
    )
    message = models.TextField(blank=True, help_text="Optional personal message")
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    responded_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(days=7)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at and self.status == 'pending'
    
    def accept(self):
        if self.status != 'pending' or self.is_expired():
            return False
        
        if not self.to_user:
            return False
        
        rel1, created1 = Relationship.objects.get_or_create(
            from_user=self.from_user,
            to_user=self.to_user,
            defaults={'relationship_type': self.relationship_type, 'is_active': True}
        )
        if not created1 and not rel1.is_active:
            rel1.is_active = True
            rel1.save()
        
        rel2, created2 = Relationship.objects.get_or_create(
            from_user=self.to_user,
            to_user=self.from_user,
            defaults={'relationship_type': self.relationship_type, 'is_active': True}
        )
        if not created2 and not rel2.is_active:
            rel2.is_active = True
            rel2.save()
        
        self.status = 'accepted'
        self.responded_at = timezone.now()
        self.save()
        return True
    
    def reject(self):
        if self.status != 'pending':
            return False
        
        self.status = 'rejected'
        self.responded_at = timezone.now()
        self.save()
        return True
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Invitation from {self.from_user.display_name} to {self.to_email}"

class SessionParticipant(models.Model):
    session = models.ForeignKey(
        Session,
        related_name='participants',
        on_delete=models.CASCADE
    )
    user = models.ForeignKey(
        'users.User',
        related_name='sessions',
        on_delete=models.CASCADE
    )
    ROLES_CHOICES = [
        ('creator','Creator'),
        ('invitee', 'Invitee'),
    ]
    role = models.CharField(
        max_length=20,
        choices=ROLES_CHOICES
    )
    invited_at = models.DateTimeField(auto_now_add=True)
    joined_at = models.DateTimeField(null=True, blank=True)
    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['session','user'],
                name='unique_session_user'
            )
        ]
    def __str__(self):
        return f"{self.user.display_name} in {self.session.session_uuid}"
    
class Round(models.Model):
    session = models.ForeignKey(
        Session,
        related_name='rounds',
        on_delete=models.CASCADE
    )
    objective_room = models.ForeignKey(
        'ObjectiveRoom',
        related_name='rounds',
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    round_index = models.PositiveBigIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Round {self.round_index} for {self.session.session_uuid}'
    
    @classmethod
    def get_max_round_index(cls, session_uuid, objective_room=None):
        if objective_room:
            # For objective rooms, get max round index within that specific objective room
            queryset = cls.objects.filter(objective_room=objective_room)
        else:
            # For session-level rounds (backward compatibility), get max across session
            queryset = cls.objects.filter(session__session_uuid=session_uuid, objective_room__isnull=True)
        
        max_row = queryset.aggregate(mx=Max('round_index'))
        return max_row['mx'] or 0
    
    class Meta:
        constraints = [
            # Allow multiple objective rooms to have rounds with same index
            models.UniqueConstraint(
                fields=['session', 'round_index'],
                condition=models.Q(objective_room__isnull=True),
                name='unique_session_round_index_legacy'
            ),
            # Ensure uniqueness within each objective room
            models.UniqueConstraint(
                fields=['objective_room', 'round_index'],
                condition=models.Q(objective_room__isnull=False),
                name='unique_objective_room_round_index'
            ),
        ]
        ordering = ['created_at']

class Message(models.Model):
    chat_round = models.ForeignKey(Round, related_name='messages',on_delete=models.CASCADE)
    sender = models.ForeignKey('users.User', on_delete=models.CASCADE)
    content = models.TextField()
    sent_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Message from {self.sender.display_name}'
    class Meta:
        ordering = ['sent_at']

class LLMResponse(models.Model):
    chat_round = models.OneToOneField(Round, related_name='llm_response', on_delete=models.CASCADE)
    content = models.TextField()
    inferenced_at = models.DateTimeField(auto_now_add=True)


class Reflection(models.Model):
    session = models.ForeignKey(Session,related_name='reflections',on_delete=models.CASCADE)
    user = models.ForeignKey('users.User',related_name='reflections',on_delete=models.CASCADE)
    feelings = models.TextField()
    expected_outcome = models.TextField()
    submitted_at = models.DateTimeField(auto_now_add=True)

    @classmethod
    def get_reflections(cls,session_uuid):
        reflections = [
            {   
                'username': reflection.user.display_name, 
                'feelings': reflection.feelings, 
                'expected_outcome': reflection.expected_outcome
            } 
            for reflection in cls.objects.filter(session__session_uuid=session_uuid)
        ]
        
        return reflections
    
    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['session', 'user'],
                name='unique_reflection_per_session_user'
            )
        ]
        ordering = ['submitted_at']

    def __str__(self):
        return f"Reflection by {self.user.display_name} on session {self.session.session_uuid}"

class SessionInvitation(models.Model):
    """Model to handle session invitations between partners"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
        ('expired', 'Expired'),
    ]
    
    invitation_uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    session = models.ForeignKey(
        Session,
        related_name='invitations',
        on_delete=models.CASCADE
    )
    from_user = models.ForeignKey(
        'users.User',
        related_name='sent_session_invitations',
        on_delete=models.CASCADE
    )
    to_user = models.ForeignKey(
        'users.User',
        related_name='received_session_invitations',
        on_delete=models.CASCADE
    )
    message = models.TextField(blank=True, help_text="Optional message for the partner")
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    responded_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(days=7)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at and self.status == 'pending'
    
    def accept(self):
        if self.status != 'pending' or self.is_expired():
            return False
        
        SessionParticipant.objects.get_or_create(
            session=self.session,
            user=self.to_user,
            defaults={'role': 'invitee'}
        )
        

        # Session will be activated when both users complete their reflections
        
        # need to add completed update somewhere

        self.status = 'accepted'
        self.responded_at = timezone.now()
        self.save()
        return True
    
    def reject(self):
        if self.status != 'pending':
            return False

        self.status = 'rejected'
        self.responded_at = timezone.now()
        self.save()

        # Mark the session as rejected (read-only)
        self.session.status = 'rejected'
        self.session.save(update_fields=['status'])

        return True
    
    class Meta:
        ordering = ['-created_at']
        constraints = [
            models.UniqueConstraint(
                fields=['session', 'to_user'],
                name='unique_session_invitation'
            )
        ]
    
    def __str__(self):
        return f"Session invitation from {self.from_user.display_name} to {self.to_user.display_name}"

class ObjectiveRoom(models.Model):
    """Model to handle individual objective-focused chat rooms"""
    session = models.ForeignKey(
        Session,
        related_name='objective_rooms',
        on_delete=models.CASCADE
    )
    objective_index = models.PositiveIntegerField(help_text="Index of this objective in the session's objectives list")
    objective_text = models.TextField(help_text="The specific objective being discussed")
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('completed', 'Completed')
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    move_to_next_votes = models.JSONField(default=dict, blank=True, help_text="Tracks votes from participants to move to next objective")
    vote_initiated_by = models.CharField(max_length=150, blank=True, help_text="Username of the person who initiated the vote")
    vote_active = models.BooleanField(default=False, help_text="Whether there's an active vote to move to next objective")

    class Meta:
        ordering = ['objective_index']
        constraints = [
            models.UniqueConstraint(
                fields=['session', 'objective_index'],
                name='unique_objective_room_per_session'
            )
        ]

    def __str__(self):
        return f"Objective {self.objective_index + 1} for Session {self.session.session_uuid}"

    def mark_as_completed(self):
        """Mark this objective as completed and advance the session to the next objective"""
        self.status = 'completed'
        self.completed_at = timezone.now()
        self.save()
        return self.session.advance_to_next_objective()
    
    def reset_vote(self):
        """Reset the voting state"""
        self.move_to_next_votes = {}
        self.vote_initiated_by = ""
        self.vote_active = False
        self.save()


class SessionSummaryResponse(models.Model):
    """Model to store user responses for the session summary ('how do you feel now')"""
    session = models.ForeignKey(
        Session,
        related_name='summary_responses',
        on_delete=models.CASCADE
    )
    user = models.ForeignKey(
        'users.User',
        related_name='session_summary_responses',
        on_delete=models.CASCADE
    )
    how_you_feel_now = models.TextField(help_text="User's response to 'How do you feel now?' at session end")
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['session', 'user'],
                name='unique_summary_response_per_session_user'
            )
        ]
        ordering = ['submitted_at']

    def __str__(self):
        return f"Summary response by {self.user.display_name} for session {self.session.session_uuid}"