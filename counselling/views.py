import json
from django.http import JsonResponse, StreamingHttpResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login, logout
from django.shortcuts import get_object_or_404

from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny

from .serializers import (LoginSerializer,RegistrationSerializer, SessionCreateSerializer, 
                          ReflectionCreateSerializer, SessionMembershipSerializer,SessionMessagesSerializer,
                          RelationshipInvitationSerializer, RelationshipInvitationListSerializer,
                          RelationshipInvitationResponseSerializer, RelationshipSerializer, UserNetworkSerializer,
                          RelationshipUpdateSerializer, SessionInvitationSerializer, 
                          SessionInvitationListSerializer, SessionInvitationResponseSerializer,
                          ObjectiveGenerationSerializer, ObjectiveRefinementSerializer, 
                          SessionCreateWithObjectivesSerializer)


from .models import Session, Reflection, Message, LLMResponse, Round, SessionParticipant, Relationship, RelationshipInvitation, SessionInvitation, ObjectiveRoom, SessionSummaryResponse
from .openrouter_service import openrouter_service
from .consumers import generate_transition_ai_message_sync

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

import json
import time
import asyncio
import threading
import traceback
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import connection, transaction

from firebase_admin import auth as firebase_auth_admin

User = get_user_model()
from django.db.models import ObjectDoesNotExist

# Import SSE components
from .sse_manager import sse_manager
from .sse_events import (
    broadcast_session_update,
    broadcast_session_invitation,
    broadcast_relationship_invitation,
    broadcast_session_status_change,
    broadcast_objective_advancement,
    broadcast_notification,
    broadcast_user_sessions_update,
    broadcast_vote_update,
    broadcast_objective_transition,
    broadcast_session_summary_generated,
    broadcast_session_summary_generating,
    broadcast_session_summary_error,
    broadcast_end_session_vote_update,
    broadcast_objective_completion
)

# LLM Objective Generation Functions
def call_objective_generation_llm(categories, context, partner_name, partner_relationship):
    """
    Call the LLM API to generate session objectives based on form data.
    Returns a list of 1-5 objectives.
    """
    objectives = []
    try:
        partner_info = f"{partner_name} ({partner_relationship})" if partner_name else None

        llm_response = openrouter_service.generate_session_objectives(context, categories, partner_info)

        # Parse the numbered list response into a list of objectives
        
        lines = llm_response.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith('-') or line.startswith('•')):
                # Remove numbering/bullets and clean up
                objective = line.split('.', 1)[-1].strip() if '.' in line else line[1:].strip()
                if objective:
                    objectives.append(objective)
        
        return objectives[:5]  # Ensure max 5 objectives
        
    except Exception as e:

        return [
            "Understand each other's perspectives on the main issue",
            "Practice active listening and empathy",
            "Identify one small step you can both take to improve"
        ]

def call_objective_refinement_llm(current_objectives, user_feedback):
    """
    Call the LLM API to refine objectives based on user feedback.
    Returns a refined list of objectives.
    """
    try:
        llm_response = openrouter_service.refine_session_objectives(current_objectives, user_feedback)

        # Parse the response into objectives list
        objectives = []
        lines = llm_response.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith('-') or line.startswith('•')):
                objective = line.split('.', 1)[-1].strip() if '.' in line else line[1:].strip()
                if objective:
                    objectives.append(objective)

        return objectives[:5]  # Ensure max 5 objectives
        
    except Exception as e:
        return current_objectives  # Return original objectives on error


class CsrfCookie(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        return Response({"detail": "CSRF cookie set"})
    
class Login(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = LoginSerializer(data=request.data,
                                     context={"request": request})
        serializer.is_valid(raise_exception=True)
        login(request, serializer.validated_data["user"])
        return Response({"success": True}, status=status.HTTP_200_OK)
    
class Logout(APIView):
    def post(self, request):
        logout(request)
        return Response({"detail": "Logged out"}, status=status.HTTP_200_OK)
    
class CurrentUser(APIView):
    def get(self, request):
        user = request.user
        return Response(
            {"display_name": user.display_name, "email": user.email}
            if user.is_authenticated
            else {"detail": "Not logged in"},
            status=status.HTTP_200_OK if user.is_authenticated else 401,
        )

class Register(APIView):
    permission_classes = (AllowAny,)  # anyone may sign up

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"success": "User registered successfully"},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class StartCounsellingSession(CreateAPIView):
    serializer_class = SessionCreateSerializer
    permission_classes = (IsAuthenticated,)

    queryset = Session.objects.none()

    def create(self,request,*args,**kwargs):
        serializer = self.get_serializer(
            data=request.data,
            context={'request':request},
        )
        serializer.is_valid(raise_exception=True)
        session = serializer.save()

        return Response(
            {"session_uuid": str(session.session_uuid)},
            status=status.HTTP_201_CREATED,
        )

# upload reflection to db
class ReflectionCreate(CreateAPIView):
    serializer_class = ReflectionCreateSerializer
    permission_classes = [IsAuthenticated]


# @TODO Better validation of empty requests <- as in possible problemss
class SessionMembership(APIView):  
    permission_classes = (IsAuthenticated,)
    def post(self, request):
        serializer = SessionMembershipSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        is_member = serializer.check_membership(request.user)
        if is_member:
            return Response(
                {"session_member": True},
                status=status.HTTP_200_OK
            )
        return Response(
            {"session_member": False},
            status=status.HTTP_403_FORBIDDEN
        )

class SessionMessages(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request, session_uuid):
        try:
            session = Session.objects.get(session_uuid=session_uuid)
        except Session.DoesNotExist:
            return Response(
                {"detail": "Session not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if not session.is_user_participant(request.user):
            return Response(
                {"detail": "You are not a participant in this session."},
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = SessionMessagesSerializer(session, context={"request": request})
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class UserSessions(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get all sessions for the authenticated user

        user = request.user

        # Get sessions where user is the creator
        created_sessions = Session.objects.filter(creator=user)

        # Get sessions where user is a participant
        participant_sessions = Session.objects.filter(participants__user=user)

        # Combine both querysets and apply distinct after combination
        all_sessions = (created_sessions | participant_sessions).distinct().order_by('-created_at')

        # Filter out sessions that are hidden by this user
        visible_sessions = [session for session in all_sessions if not session.is_hidden_by_user(user)]

        sessions_data = []
        for session in visible_sessions:
            # Get other participants for this session
            other_participants = SessionParticipant.objects.filter(
                session=session
            ).exclude(user=user).select_related('user')
            
            # Get latest activity (last message or session creation)
            latest_message = Message.objects.filter(chat_round__session=session).order_by('-sent_at').first()
            latest_activity = latest_message.sent_at if latest_message else session.created_at
            
            # Count total messages in session
            message_count = Message.objects.filter(chat_round__session=session).count()
            
            session_data = {
                'session_uuid': str(session.session_uuid),
                'topic': session.categories,
                'status': session.status,
                'created_at': session.created_at,
                'latest_activity': latest_activity,
                'message_count': message_count,
                'is_creator': session.creator == user,
                # Why use username to check if creator is user?
                'creator': session.creator.display_name,
                'other_participants': [
                    {
                        'display_name': participant.user.display_name,
                        'joined_at': participant.joined_at
                    } 
                    for participant in other_participants
                ]
            }
            sessions_data.append(session_data)
        
        return Response({
            'sessions': sessions_data
        }, status=status.HTTP_200_OK)

class SendRelationshipInvitation(CreateAPIView):
    # send a relationship invitation to someone by email
    serializer_class = RelationshipInvitationSerializer
    permission_classes = [IsAuthenticated]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        invitation = serializer.save()
        
        # Broadcast relationship invitation if user exists
        try:
            broadcast_relationship_invitation(invitation)
        except Exception as e:
            pass
        
        # could add email sending functionality
        # send_invitation_email(invitation)
        
        return Response({
            'message': 'Invitation sent successfully',
            'invitation_uuid': str(invitation.invitation_uuid)
        }, status=status.HTTP_201_CREATED)

class RespondToRelationshipInvitation(APIView):
    """Accept or reject a relationship invitation"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = RelationshipInvitationResponseSerializer(
            data=request.data, 
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        invitation_uuid = serializer.validated_data['invitation_uuid']
        action = serializer.validated_data['action']
        
        invitation = RelationshipInvitation.objects.get(invitation_uuid=invitation_uuid)
        
        # Set to_user if it's not already set (user signed up after invitation)
        if not invitation.to_user:
            invitation.to_user = request.user
            invitation.save()
        
        if action == 'accept':
            success = invitation.accept()
            if success:
                # Broadcast notification to invitation sender - DISABLED
                # try:
                #     broadcast_notification(
                #         invitation.from_user.id,
                #         'Relationship Invitation Accepted',
                #         f'{request.user.display_name} accepted your relationship invitation',
                #         'success'
                #     )
                # except Exception as e:
                #     print(f"Failed to broadcast relationship acceptance: {e}")
                
                return Response({
                    'message': 'Invitation accepted successfully',
                    'relationship_created': True
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'Failed to accept invitation'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        elif action == 'reject':
            success = invitation.reject()
            if success:
                # Broadcast notification to invitation sender - DISABLED
                # try:
                #     broadcast_notification(
                #         invitation.from_user.id,
                #         'Relationship Invitation Rejected',
                #         f'{request.user.display_name} rejected your relationship invitation',
                #         'info'
                #     )
                # except Exception as e:
                #     print(f"Failed to broadcast relationship rejection: {e}")
                
                return Response({
                    'message': 'Invitation rejected'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'Failed to reject invitation'
                }, status=status.HTTP_400_BAD_REQUEST)

class UserNetwork(APIView):
    """Get user's complete network including relationships and invitations"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        # Get user's relationships
        relationships = Relationship.objects.filter(
            from_user=user
        ).select_related('to_user')
        
        # Get sent invitations (only pending ones for UI)
        sent_invitations = RelationshipInvitation.objects.filter(
            from_user=user
        ).order_by('-created_at')
        
        # Get received invitations
        received_invitations = RelationshipInvitation.objects.filter(
            to_email=user.email,
            status='pending'
        ).order_by('-created_at')
        
        data = {
            'relationships': RelationshipSerializer(relationships, many=True).data,
            'sent_invitations': RelationshipInvitationListSerializer(sent_invitations, many=True).data,
            'received_invitations': RelationshipInvitationListSerializer(received_invitations, many=True).data
        }
        
        return Response(data, status=status.HTTP_200_OK)

class CancelRelationshipInvitation(APIView):
    """Cancel a pending relationship invitation"""
    permission_classes = [IsAuthenticated]
    
    def delete(self, request, invitation_uuid):
        try:
            invitation = RelationshipInvitation.objects.get(
                invitation_uuid=invitation_uuid,
                from_user=request.user,
                status='pending'
            )
        except RelationshipInvitation.DoesNotExist:
            return Response(
                {"detail": "Invitation not found or cannot be cancelled."},
                status=status.HTTP_404_NOT_FOUND,
            )
        
        # Update invitation status to cancelled (or delete it)
        invitation.status = 'rejected'  # We'll use rejected to indicate cancelled
        invitation.responded_at = timezone.now()
        invitation.save()
        
        return Response(
            {"message": "Invitation cancelled successfully"},
            status=status.HTTP_200_OK
        )

class UserRelationships(APIView):
    """Get only active relationships for the user"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        relationships = Relationship.objects.filter(
            from_user=user
        ).select_related('to_user')
        
        serializer = RelationshipSerializer(relationships, many=True)
        return Response({
            'relationships': serializer.data
        }, status=status.HTTP_200_OK)

class DeleteUserAccount(APIView):
    """Delete user account and all associated data"""
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user

        try:
            # Delete the user (this will cascade to related objects)
            # This includes sessions, messages, relationships, etc.
            user.delete()

            return Response({
                'success': True,
                'message': 'User account and all associated data deleted successfully'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'error': 'Failed to delete user account',
                'detail': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RemoveRelationship(APIView):
    # Remove/delete a relationship
    permission_classes = [IsAuthenticated]
    
    def delete(self, request, relationship_id):
        try:
            relationship = Relationship.objects.get(
                id=relationship_id,
                from_user=request.user
            )
            
            # Get the users involved
            user1 = relationship.from_user
            user2 = relationship.to_user
            
            # Delete both directions of the relationship
            deleted_count_1, _ = Relationship.objects.filter(
                from_user=user1,
                to_user=user2
            ).delete()
            
            deleted_count_2, _ = Relationship.objects.filter(
                from_user=user2,
                to_user=user1
            ).delete()
            
            total_deleted = deleted_count_1 + deleted_count_2
            
            return Response({
                'message': f'Relationship deleted successfully. Removed {total_deleted} records.'
            }, status=status.HTTP_200_OK)
            
        except Relationship.DoesNotExist:
            return Response({
                'error': 'Relationship not found'
            }, status=status.HTTP_404_NOT_FOUND)

class UserRelationshipsForSession(APIView):
    # Get user's relationships that can be invited to counselling sessions
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        relationships = Relationship.objects.filter(
            from_user=user
        ).select_related('to_user')
        
        # Format for session invitation use
        session_contacts = []
        for relationship in relationships:
            contact = {
                'user_id': relationship.to_user.id,
                'display_name': relationship.to_user.display_name,
                'email': relationship.to_user.email,
                'relationship_type': relationship.get_relationship_type_display(),
                'relationship_type_code': relationship.relationship_type
            }
            session_contacts.append(contact)
        
        return Response({
            'contacts': session_contacts,
            'total_count': len(session_contacts)
        }, status=status.HTTP_200_OK)

class RelationshipDetail(APIView):
    # Get and update relationship details
    permission_classes = [IsAuthenticated]
    
    def get(self, request, relationship_id):
        try:
            relationship = Relationship.objects.get(
                id=relationship_id,
                from_user=request.user
            )
            serializer = RelationshipSerializer(relationship)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except Relationship.DoesNotExist:
            return Response({
                'error': 'Relationship not found'
            }, status=status.HTTP_404_NOT_FOUND)
    
    def put(self, request, relationship_id):
        try:
            relationship = Relationship.objects.get(
                id=relationship_id,
                from_user=request.user
            )
            
            serializer = RelationshipUpdateSerializer(
                relationship, 
                data=request.data, 
                partial=True
            )
            
            if serializer.is_valid():
                updated_relationship = serializer.save()
                
                # Also update the reverse relationship if it exists
                try:
                    reverse_relationship = Relationship.objects.get(
                        from_user=relationship.to_user,
                        to_user=relationship.from_user
                    )
                    # Update relationship type for reverse relationship too
                    reverse_relationship.relationship_type = updated_relationship.relationship_type
                    reverse_relationship.save()
                except Relationship.DoesNotExist:
                    pass
                
                return Response(
                    RelationshipSerializer(updated_relationship).data,
                    status=status.HTTP_200_OK
                )
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Relationship.DoesNotExist:
            return Response({
                'error': 'Relationship not found'
            }, status=status.HTTP_404_NOT_FOUND)

class RespondToSessionInvitation(APIView):
    # Accept or reject a session invitation
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = SessionInvitationResponseSerializer(
            data=request.data, 
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        invitation_uuid = serializer.validated_data['invitation_uuid']
        action = serializer.validated_data['action']
        
        invitation = SessionInvitation.objects.get(invitation_uuid=invitation_uuid)
        
        if action == 'accept':
            success = invitation.accept()
            if success:
                # Broadcast session update to creator
                try:
                    broadcast_session_update(invitation.session, 'session_invitation_accepted', {
                        'accepted_by': request.user.display_name,
                        'message': f'{request.user.display_name} accepted your session invitation'
                    })
                except Exception as e:
                    pass
                
                return Response({
                    'message': 'Session invitation accepted successfully',
                    'session_uuid': str(invitation.session.session_uuid),
                    'redirect_to': 'reflection'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'Failed to accept session invitation'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        elif action == 'reject':
            success = invitation.reject()
            if success:
                # Broadcast session status change to creator (session is now read-only)
                try:
                    broadcast_session_update(invitation.session, 'session_invitation_rejected', {
                        'rejected_by': request.user.display_name,
                        'message': f'{request.user.display_name} rejected your session invitation',
                        'session_status': 'rejected'
                    })
                except Exception as e:
                    pass

                return Response({
                    'message': 'Session invitation rejected'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'Failed to reject session invitation'
                }, status=status.HTTP_400_BAD_REQUEST)

class UserSessionInvitations(APIView):
    # Get user's session invitations (sent and received)
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        # Get sent session invitations
        sent_invitations = SessionInvitation.objects.filter(
            from_user=user
        ).select_related('session', 'to_user').order_by('-created_at')
        
        # Get received session invitations
        received_invitations = SessionInvitation.objects.filter(
            to_user=user,
            status='pending'
        ).select_related('session', 'from_user').order_by('-created_at')
        
        data = {
            'sent_invitations': SessionInvitationListSerializer(sent_invitations, many=True).data,
            'received_invitations': SessionInvitationListSerializer(received_invitations, many=True).data
        }
        
        return Response(data, status=status.HTTP_200_OK)

class SessionTurnState(APIView):
    # Get the current turn state for a session
    permission_classes = [IsAuthenticated]
    
    def get(self, request, session_uuid):
        try:
            session = Session.objects.get(session_uuid=session_uuid)
        except Session.DoesNotExist:
            return Response(
                {"detail": "Session not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        
        if not session.is_user_participant(request.user):
            return Response(
                {"detail": "You are not a participant in this session."},
                status=status.HTTP_403_FORBIDDEN,
            )
        
        turn_state = session.get_turn_state_for_user(request.user)
        
        return Response({
            'turn_state': turn_state
        }, status=status.HTTP_200_OK)

class DeleteSession(APIView):
    """Delete a session - any participant can hide it from their view.
    Special case: Creator can permanently delete pending or rejected sessions immediately."""
    permission_classes = [IsAuthenticated]

    def delete(self, request, session_uuid):
        try:
            session = Session.objects.get(session_uuid=session_uuid)
        except Session.DoesNotExist:
            return Response(
                {"detail": "Session not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Check if user is a participant
        if not session.is_user_participant(request.user):
            return Response(
                {"detail": "You are not a participant in this session."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Special case: If creator deletes a pending or rejected session, hard delete immediately
        if session.creator == request.user and session.status in ['pending', 'rejected']:
            # Get session invitations before deletion to notify invitees
            session_invitations = list(session.invitations.filter(status='pending').select_related('to_user'))

            # Broadcast session deletion to all participants and invitees
            try:
                # Get all participants
                participants = SessionParticipant.objects.filter(session=session).select_related('user')
                user_ids = {p.user.id for p in participants}

                # Add invitees who haven't joined yet
                for invitation in session_invitations:
                    user_ids.add(invitation.to_user.id)

                # Remove the creator from notifications (they initiated the deletion)
                user_ids.discard(session.creator.id)

                if user_ids:
                    data = {
                        'type': 'session_deleted',
                        'session_uuid': str(session.session_uuid),
                        'message': f'Session cancelled by {session.creator.display_name}'
                    }

                    # Broadcast to affected users
                    sse_manager.broadcast_to_users(user_ids, 'session_deleted', data)

                    # Also trigger session invitation refresh for invitees
                    for invitation in session_invitations:
                        sse_manager.broadcast_to_user(invitation.to_user.id, 'session_invitation', {
                            'type': 'session_invitation_cancelled',
                            'message': 'Session invitation list updated'
                        })

            except Exception as e:
                pass

            session.delete()
            return Response({
                "message": f"{session.status.capitalize()} session permanently deleted"
            }, status=status.HTTP_200_OK)

        # Hide the session for this user (soft delete)
        success = session.hide_for_user(request.user)
        if not success:
            return Response(
                {"detail": "Failed to hide session."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Check if all participants have now hidden the session
        if session.should_be_hard_deleted():
            # Hard delete the session (this will cascade to related objects)
            # No SSE broadcast needed since both users already removed it from their view
            session.delete()

            return Response({
                "message": "Session permanently deleted (all participants removed it)"
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "message": "Session hidden from your view"
            }, status=status.HTTP_200_OK)

# Objective Generation Views
class GenerateObjectives(APIView):
    """Generate session objectives based on form data"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ObjectiveGenerationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        categories = serializer.validated_data['categories']
        context = serializer.validated_data.get('context', '')
        partner_name = serializer.validated_data.get('partner_name', '')
        partner_relationship = serializer.validated_data.get('partner_relationship', '')
        
        # Generate objectives using LLM
        objectives = call_objective_generation_llm(
            categories, context, partner_name, partner_relationship
        )
        
        return Response({
            'objectives': objectives,
            'message': 'Objectives generated successfully'
        }, status=status.HTTP_200_OK)

class RefineObjectives(APIView):
    """Refine objectives based on user feedback"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ObjectiveRefinementSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        current_objectives = serializer.validated_data['current_objectives']
        user_feedback = serializer.validated_data['user_feedback']
        
        # Refine objectives using LLM
        refined_objectives = call_objective_refinement_llm(current_objectives, user_feedback)
        
        return Response({
            'objectives': refined_objectives,
            'message': 'Objectives refined successfully'
        }, status=status.HTTP_200_OK)

class CreateSessionWithObjectives(CreateAPIView):
    """Create session with finalized objectives"""
    serializer_class = SessionCreateWithObjectivesSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Create session
        session = Session.objects.create(
            creator=request.user,
            categories=serializer.validated_data['categories'],
            context=serializer.validated_data['context'],
            objectives=serializer.validated_data['objectives']
        )

        # Create first objective room
        ObjectiveRoom.objects.create(
            session=session,
            objective_index=0,
            objective_text=session.objectives[0]
        )
        
        # Create session participant for creator
        SessionParticipant.objects.create(
            session=session,
            user=request.user,
            role='creator',
            joined_at=timezone.now()
        )
        
        # Create and send invitation to partner
        partner_id = serializer.validated_data['partner_id']
        partner_message = serializer.validated_data.get('partner_message', '')
        
        partner = get_object_or_404(get_user_model(), id=partner_id)
        
        invitation = SessionInvitation.objects.create(
            session=session,
            from_user=request.user,
            to_user=partner,
            message=partner_message,
            expires_at=timezone.now() + timezone.timedelta(days=7)
        )
        
        # Broadcast session invitation to partner
        try:
            result = broadcast_session_invitation(invitation)
        except Exception as e:
            pass
        
        # Return session UUID
        return Response({
            'session_uuid': session.session_uuid,
            'invitation_uuid': invitation.invitation_uuid
        }, status=status.HTTP_201_CREATED)
        

class SessionDetail(APIView):
    """Get session details including objectives and current objective index"""
    permission_classes = [IsAuthenticated]
    
    def check_all_voted_to_end(self, session):
        """Check if all participants have voted to end the session"""
        if not session.end_session_votes:
            return False
        participants = SessionParticipant.objects.filter(session=session)
        return all(
            participant.user.username in session.end_session_votes
            for participant in participants
        )

    def is_in_summary_phase(self, session):
        """Check if session is in summary phase"""
        # If summary is already generated, definitely in summary phase
        if session.summary_generated:
            return True

        # If currently voting to end session, not yet in summary phase
        if self.check_all_voted_to_end(session):
            return True

        # Check if we're on the last objective and it's completed
        if session.is_on_last_objective():
            last_objective_room = session.get_current_objective_room()
            if last_objective_room and last_objective_room.status == 'completed':
                return True

        return False
    
    def get(self, request, session_uuid):
        try:
            session = get_object_or_404(Session, session_uuid=session_uuid)
            
            # Check if user is a participant
            if not SessionParticipant.objects.filter(session=session, user=request.user).exists():
                return Response({'error': 'Not a participant in this session'}, status=status.HTTP_403_FORBIDDEN)
            
            # Get message counts for all objectives
            objective_message_counts = {}
            for objective_room in session.objective_rooms.all():
                # Count messages in this objective room
                message_count = sum(
                    round_obj.messages.count()
                    for round_obj in objective_room.rounds.all()
                )

                # For objective 0, also include session-level messages (initial greeting)
                if objective_room.objective_index == 0:
                    session_level_message_count = sum(
                        round_obj.messages.count() + (1 if hasattr(round_obj, 'llm_response') else 0)
                        for round_obj in session.rounds.filter(objective_room__isnull=True)
                    )
                    message_count += session_level_message_count

                objective_message_counts[objective_room.objective_index] = message_count
            
            # Get vote initiator display name
            vote_initiated_by_display = ""
            if session.end_session_vote_initiated_by:
                try:
                    initiator_user = User.objects.get(username=session.end_session_vote_initiated_by)
                    vote_initiated_by_display = initiator_user.display_name
                except User.DoesNotExist:
                    vote_initiated_by_display = session.end_session_vote_initiated_by
            
            # Calculate completed objectives count
            # When in summary phase, current_objective_index equals total objectives
            # When in normal progression, current_objective_index equals completed count
            is_summary_phase = self.is_in_summary_phase(session)
            completed_objectives = session.current_objective_index

            return Response({
                'session_uuid': session.session_uuid,
                'objectives': session.objectives,
                'current_objective_index': session.current_objective_index,
                'status': session.status,
                'categories': session.categories,
                'context': session.context,
                'created_at': session.created_at,
                'objective_message_counts': objective_message_counts,  # Add message counts
                'end_session_votes': session.end_session_votes or {},
                'end_session_vote_active': session.end_session_vote_active,
                'end_session_vote_initiated_by': session.end_session_vote_initiated_by or '',
                'end_session_vote_initiated_by_display': vote_initiated_by_display,
                'is_in_summary_phase': is_summary_phase,
                'completed_objectives': completed_objectives,  # Add completed objectives count
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ObjectiveMessages(APIView):
    """Get messages for a specific objective room"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, session_uuid, objective_index):
        try:
            session = get_object_or_404(Session, session_uuid=session_uuid)
            
            # Check if user is a participant
            if not SessionParticipant.objects.filter(session=session, user=request.user).exists():
                return Response({'error': 'Not a participant in this session'}, status=status.HTTP_403_FORBIDDEN)
            
            # Get or create objective room
            objective_room, created = ObjectiveRoom.objects.get_or_create(
                session=session,
                objective_index=objective_index,
                defaults={
                    'objective_text': session.objectives[objective_index] if objective_index < len(session.objectives) else '',
                    'status': 'active' if objective_index == session.current_objective_index else 'locked'
                }
            )
            
            # Note: Initial AI message generation is handled by the transition logic in VoteToMoveNext view
            # Removing redundant call to prevent duplicate LLM responses during transitions
            
            # Get messages for this objective room
            messages = []

            # For objective 0, also include session-level messages (initial greeting)
            if objective_index == 0:
                # Get session-level rounds (initial greeting)
                session_rounds = Round.objects.filter(
                    session=session,
                    objective_room__isnull=True
                ).prefetch_related('messages__sender', 'llm_response').order_by('round_index')

                for round_obj in session_rounds:
                    # Add human messages
                    for message in round_obj.messages.order_by('sent_at'):
                        messages.append({
                            'content': message.content,
                            'sender': {
                                'uid': message.sender.username,
                                'name': message.sender.display_name
                            },
                            'sent_at': message.sent_at,
                            'type': 'human'
                        })

                    # Add AI response if exists (this is the initial greeting)
                    if hasattr(round_obj, 'llm_response'):
                        try:
                            messages.append({
                                'content': round_obj.llm_response.content,
                                'sender': 'llm',
                                'sent_at': round_obj.llm_response.inferenced_at,
                                'type': 'ai'
                            })
                        except ObjectDoesNotExist:
                            pass

            # Get objective-specific rounds
            rounds = Round.objects.filter(
                session=session,
                objective_room=objective_room
            ).prefetch_related('messages__sender', 'llm_response').order_by('round_index')

            for round_obj in rounds:
                # Add human messages
                for message in round_obj.messages.order_by('sent_at'):
                    messages.append({
                        'content': message.content,
                        'sender': {
                            'uid': message.sender.username,
                            'name': message.sender.display_name
                        },
                        'sent_at': message.sent_at,
                        'type': 'human'
                    })

                # Add AI response if exists
                if hasattr(round_obj, 'llm_response'):
                    try:
                        messages.append({
                            'content': round_obj.llm_response.content,
                            'sender': 'llm',
                            'sent_at': round_obj.llm_response.inferenced_at,
                            'type': 'ai'
                        })
                    except ObjectDoesNotExist:
                        pass

            # Sort all messages by timestamp to maintain chronological order
            messages.sort(key=lambda x: x['sent_at'])

            # Count messages for this objective room (now includes session-level messages for objective 0)
            message_count = len(messages)  # Use the messages list which includes both human and AI messages
            
            # Get voting status for moving to next objective
            move_to_next_votes = objective_room.move_to_next_votes or {}
            has_voted_to_move_next = request.user.username in move_to_next_votes
            
            # Check if this objective is read-only (completed or not current)
            is_read_only = objective_room.status == 'completed' or objective_index < session.current_objective_index
            
            # Get vote initiator display name
            vote_initiated_by_display = ""
            if objective_room.vote_initiated_by:
                try:
                    initiator_user = User.objects.get(username=objective_room.vote_initiated_by)
                    vote_initiated_by_display = initiator_user.display_name
                except User.DoesNotExist:
                    vote_initiated_by_display = objective_room.vote_initiated_by
            
            return Response({
                'messages': messages,
                'message_count': message_count,
                'move_to_next_votes': move_to_next_votes,
                'has_voted_to_move_next': has_voted_to_move_next,
                'vote_active': objective_room.vote_active,
                'vote_initiated_by': objective_room.vote_initiated_by,
                'vote_initiated_by_display': vote_initiated_by_display,
                'is_read_only': is_read_only,
                'objective_room': {
                    'objective_index': objective_room.objective_index,
                    'objective_text': objective_room.objective_text,
                    'status': objective_room.status,
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class VoteToMoveNext(APIView):
    """Vote to move to the next objective or reject a vote"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, session_uuid, objective_index):
        try:
            session = get_object_or_404(Session, session_uuid=session_uuid)

            # Check if session is read-only
            if session.is_read_only():
                return Response({'error': 'Cannot vote in read-only sessions'}, status=status.HTTP_403_FORBIDDEN)

            # Check if user is a participant
            if not SessionParticipant.objects.filter(session=session, user=request.user).exists():
                return Response({'error': 'Not a participant in this session'}, status=status.HTTP_403_FORBIDDEN)
            
            # Get objective room
            objective_room = get_object_or_404(
                ObjectiveRoom,
                session=session,
                objective_index=objective_index
            )
            
            vote_action = request.data.get('action', 'vote')  # 'vote' or 'reject'
            
            # Initialize move_to_next_votes if None
            if objective_room.move_to_next_votes is None:
                objective_room.move_to_next_votes = {}
            
            if vote_action == 'reject':
                # Reset the vote if user rejects
                objective_room.reset_vote()
                
                # Broadcast vote rejection to all participants
                try:
                    broadcast_vote_update(session, objective_room, request.user, 'vote_rejected')
                except Exception as e:
                    pass
                
                return Response({
                    'message': 'Vote rejected. Continuing with current objective.',
                    'vote_active': False,
                    'move_to_next_votes': {},
                    'vote_initiated_by': ''
                }, status=status.HTTP_200_OK)
            
            else:  # vote_action == 'vote'
                # If no active vote, this user is initiating the vote
                if not objective_room.vote_active:
                    objective_room.vote_initiated_by = request.user.username
                    objective_room.vote_active = True
                
                # Add user's vote
                objective_room.move_to_next_votes[request.user.username] = True
                objective_room.save()
                
                # Check if all participants have voted
                participants = SessionParticipant.objects.filter(session=session)
                all_voted = all(
                    participant.user.username in objective_room.move_to_next_votes
                    for participant in participants
                )
                
                # Get initiator display name
                initiator_display_name = request.user.display_name
                if objective_room.vote_initiated_by != request.user.username:
                    try:
                        initiator_user = User.objects.get(username=objective_room.vote_initiated_by)
                        initiator_display_name = initiator_user.display_name
                    except User.DoesNotExist:
                        initiator_display_name = objective_room.vote_initiated_by
                
                # Broadcast vote update to all participants
                try:
                    broadcast_vote_update(session, objective_room, request.user, 'vote_cast')
                except Exception as e:
                    pass
                
                # If all participants have voted, automatically move to next objective
                if all_voted:
                    # Mark current objective as completed and reset vote state
                    old_objective_index = session.current_objective_index
                    objective_room.status = 'completed'
                    objective_room.reset_vote()
                    
                    # Move to next objective
                    next_objective_index = session.current_objective_index + 1
                    if next_objective_index < len(session.objectives):
                        session.current_objective_index = next_objective_index
                        session.save()
                        
                        # Create or activate next objective room
                        next_objective_room, created = ObjectiveRoom.objects.get_or_create(
                            session=session,
                            objective_index=next_objective_index,
                            defaults={
                                'objective_text': session.objectives[next_objective_index],
                                'status': 'active'
                            }
                        )
                        
                        if not created:
                            next_objective_room.status = 'active'
                            next_objective_room.save()

                        # Broadcast objective transition IMMEDIATELY (no AI generation delay)
                        try:
                            broadcast_objective_transition(session, old_objective_index, next_objective_index)
                        except Exception as e:
                            pass

                        # Generate AI message asynchronously in background
                        def generate_ai_async():
                            try:
                                # Show typing indicator
                                channel_layer = get_channel_layer()
                                async_to_sync(channel_layer.group_send)(
                                    f"{session.session_uuid}_session",
                                    {
                                        "type": "llm_typing_start",
                                        "message": f"AI Counselor is joining objective {next_objective_index + 1}..."
                                    }
                                )

                                # Generate message using existing function
                                ai_message = generate_transition_ai_message_sync(session, next_objective_room)

                                # Stop typing and send message
                                async_to_sync(channel_layer.group_send)(
                                    f"{session.session_uuid}_session",
                                    {"type": "llm_typing_stop"}
                                )
                                async_to_sync(channel_layer.group_send)(
                                    f"{session.session_uuid}_session",
                                    {
                                        "type": "chat_message",
                                        "sender": {"uid": "llm", "name": "AI Counselor"},
                                        "content": ai_message
                                    }
                                )
                            except Exception as e:
                                # Send fallback message
                                try:
                                    objective_number = next_objective_room.objective_index + 1
                                    fallback_message = f"Welcome to objective {objective_number}! Let's focus on: {next_objective_room.objective_text}. How are you both feeling about working on this together?"

                                    async_to_sync(channel_layer.group_send)(
                                        f"{session.session_uuid}_session",
                                        {"type": "llm_typing_stop"}
                                    )
                                    async_to_sync(channel_layer.group_send)(
                                        f"{session.session_uuid}_session",
                                        {
                                            "type": "chat_message",
                                            "sender": {"uid": "llm", "name": "AI Counselor"},
                                            "content": fallback_message
                                        }
                                    )
                                except Exception as fallback_error:
                                    pass

                        # Start async AI generation
                        thread = threading.Thread(target=generate_ai_async)
                        thread.daemon = True
                        thread.start()
                        
                        return Response({
                            'message': 'All participants voted. Moving to next objective.',
                            'moved_to_next': True,
                            'current_objective_index': session.current_objective_index,
                            'session_completed': False
                        }, status=status.HTTP_200_OK)
                    else:
                        # Session completed - but don't redirect users, they need to do summary
                        session.status = 'completed'
                        session.save()

                        # Broadcast session status change instead of completion (no redirect)
                        try:
                            broadcast_session_status_change(session, 'active', 'completed')
                        except Exception as e:
                            pass
                        
                        return Response({
                            'message': 'Session completed successfully',
                            'moved_to_next': False,
                            'current_objective_index': session.current_objective_index,
                            'session_completed': True
                        }, status=status.HTTP_200_OK)
                
                return Response({
                    'message': 'Vote recorded successfully',
                    'move_to_next_votes': objective_room.move_to_next_votes,
                    'vote_active': objective_room.vote_active,
                    'vote_initiated_by': objective_room.vote_initiated_by,
                    'vote_initiated_by_display': initiator_display_name,
                    'all_voted': all_voted,
                    'votes_count': len([v for v in objective_room.move_to_next_votes.values() if v])
                }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class MoveToNextObjective(APIView):
    """Move to the next objective (after all participants have voted)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, session_uuid):
        try:
            session = get_object_or_404(Session, session_uuid=session_uuid)
            
            # Check if user is a participant
            if not SessionParticipant.objects.filter(session=session, user=request.user).exists():
                return Response({'error': 'Not a participant in this session'}, status=status.HTTP_403_FORBIDDEN)
            
            # Get current objective room
            current_objective_room = get_object_or_404(
                ObjectiveRoom,
                session=session,
                objective_index=session.current_objective_index
            )
            
            # Check if all participants have voted
            participants = SessionParticipant.objects.filter(session=session)
            if not all(
                participant.user.username in (current_objective_room.move_to_next_votes or {})
                for participant in participants
            ):
                return Response({'error': 'Not all participants have voted'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Mark current objective as completed and reset vote state
            current_objective_room.status = 'completed'
            current_objective_room.reset_vote()
            
            # Store old objective index for transition broadcast
            old_objective_index = session.current_objective_index

            # Move to next objective
            next_objective_index = session.current_objective_index + 1
            if next_objective_index < len(session.objectives):
                session.current_objective_index = next_objective_index
                session.save()
                
                # Create or activate next objective room
                next_objective_room, created = ObjectiveRoom.objects.get_or_create(
                    session=session,
                    objective_index=next_objective_index,
                    defaults={
                        'objective_text': session.objectives[next_objective_index],
                        'status': 'active'
                    }
                )

                if not created:
                    next_objective_room.status = 'active'
                    next_objective_room.save()

                # Broadcast transition immediately (without AI message for speed)
                broadcast_objective_transition(
                    session,
                    old_objective_index,
                    session.current_objective_index
                )

                # Generate AI message asynchronously with typing indicator
                def generate_ai_async():
                    try:
                        # Generate message using existing function
                        ai_message = generate_transition_ai_message_sync(session, next_objective_room)

                        # Send message
                        channel_layer = get_channel_layer()
                        async_to_sync(channel_layer.group_send)(
                            f"{session.session_uuid}_session",
                            {
                                "type": "chat_message",
                                "sender": {"uid": "llm", "name": "AI Counselor"},
                                "content": ai_message
                            }
                        )

                    except Exception as e:
                        # Send fallback message
                        try:
                            objective_number = next_objective_room.objective_index + 1
                            fallback_message = f"Welcome to objective {objective_number}! Let's focus on: {next_objective_room.objective_text}. How are you both feeling about working on this together?"

                            async_to_sync(channel_layer.group_send)(
                                f"{session.session_uuid}_session",
                                {
                                    "type": "chat_message",
                                    "sender": {"uid": "llm", "name": "AI Counselor"},
                                    "content": fallback_message
                                }
                            )
                        except Exception as fallback_error:
                            pass

                # Start async AI generation
                thread = threading.Thread(target=generate_ai_async)
                thread.daemon = True
                thread.start()

                return Response({
                    'message': 'Moved to next objective successfully',
                    'current_objective_index': session.current_objective_index,
                    'session_completed': False
                }, status=status.HTTP_200_OK)
            else:
                # Session completed
                session.status = 'completed'
                session.save()
                
                return Response({
                    'message': 'Session completed successfully',
                    'current_objective_index': session.current_objective_index,
                    'session_completed': True
                }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class CompleteObjective(APIView):
    """Mark an objective as completed and advance to next one"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, session_uuid, objective_index):
        try:
            session = get_object_or_404(Session, session_uuid=session_uuid)
            
            # Check if user is a participant
            if not SessionParticipant.objects.filter(session=session, user=request.user).exists():
                return Response({'error': 'Not a participant in this session'}, status=status.HTTP_403_FORBIDDEN)
            
            # Get objective room
            objective_room = get_object_or_404(
                ObjectiveRoom,
                session=session,
                objective_index=objective_index
            )
            
            # Mark as completed
            objective_room.mark_as_completed()
            
            return Response({
                'message': 'Objective completed successfully',
                'next_objective_index': session.current_objective_index,
                'session_completed': session.current_objective_index >= len(session.objectives)
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class VoteToEndSession(APIView):
    """Vote to end the session or reject a vote"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, session_uuid):
        try:
            session = get_object_or_404(Session, session_uuid=session_uuid)

            # Check if session is read-only
            if session.is_read_only():
                return Response({'error': 'Cannot vote in read-only sessions'}, status=status.HTTP_403_FORBIDDEN)

            # Check if user is a participant
            if not SessionParticipant.objects.filter(session=session, user=request.user).exists():
                return Response({'error': 'Not a participant in this session'}, status=status.HTTP_403_FORBIDDEN)
            
            # Only allow voting on the last objective
            if not session.is_on_last_objective():
                return Response({'error': 'Can only vote to end session on the last objective'}, status=status.HTTP_400_BAD_REQUEST)
            
            vote_action = request.data.get('action', 'vote')  # 'vote' or 'reject'
            
            # Initialize end_session_votes if None
            if session.end_session_votes is None:
                session.end_session_votes = {}
            
            if vote_action == 'reject':
                # Reset the vote if user rejects
                session.reset_end_session_vote()
                
                # Broadcast vote rejection to all participants
                try:
                    broadcast_end_session_vote_update(session, request.user, 'vote_rejected')
                except Exception as e:
                    pass
                
                return Response({
                    'message': 'Vote rejected. Continuing with session.',
                    'vote_active': False,
                    'end_session_votes': {},
                    'vote_initiated_by': ''
                }, status=status.HTTP_200_OK)
            
            else:  # vote_action == 'vote'
                # If no active vote, this user is initiating the vote
                if not session.end_session_vote_active:
                    session.end_session_vote_initiated_by = request.user.username
                    session.end_session_vote_active = True
                    # Only record the vote, don't check for "all voted" yet since this is just the proposal
                    session.end_session_votes[request.user.username] = True
                    session.save()
                    
                    # Broadcast vote initiation to all participants
                    try:
                        broadcast_end_session_vote_update(session, request.user, 'vote_initiated')
                    except Exception as e:
                        pass
                    
                    return Response({
                        'message': 'Vote to end session initiated. Waiting for other participants.',
                        'end_session_votes': session.end_session_votes,
                        'vote_active': session.end_session_vote_active,
                        'vote_initiated_by': session.end_session_vote_initiated_by,
                        'vote_initiated_by_display': request.user.display_name,
                    }, status=status.HTTP_200_OK)
                
                else:
                    # Vote is already active, this user is responding to the proposal
                    if request.user.username == session.end_session_vote_initiated_by:
                        return Response({'error': 'You already initiated this vote'}, status=status.HTTP_400_BAD_REQUEST)
                    
                    # Add user's vote (they're accepting the proposal)
                    session.end_session_votes[request.user.username] = True
                    session.save()
                    
                    # Check if all participants have now voted
                    participants = SessionParticipant.objects.filter(session=session)
                    all_voted = all(
                        participant.user.username in session.end_session_votes
                        for participant in participants
                    )
                    
                    # Get initiator display name
                    initiator_display_name = request.user.display_name
                    if session.end_session_vote_initiated_by != request.user.username:
                        try:
                            initiator_user = User.objects.get(username=session.end_session_vote_initiated_by)
                            initiator_display_name = initiator_user.display_name
                        except User.DoesNotExist:
                            initiator_display_name = session.end_session_vote_initiated_by
                    
                    # Broadcast vote update to all participants
                    try:
                        broadcast_end_session_vote_update(session, request.user, 'vote_cast')
                    except Exception as e:
                        pass
                    
                    # If all participants have voted, move to summary phase
                    if all_voted:
                        # Mark the last objective as completed before moving to summary
                        current_objective_room = session.get_current_objective_room()
                        if current_objective_room and current_objective_room.status != 'completed':
                            current_objective_room.status = 'completed'
                            current_objective_room.completed_at = timezone.now()
                            current_objective_room.save()

                            # Broadcast objective completion to update UI state
                            try:
                                broadcast_objective_completion(session, current_objective_room.objective_index)
                            except Exception as e:
                                pass

                        # Update session to reflect that we've moved beyond all objectives
                        session.current_objective_index = len(session.objectives)
                        session.save()

                        # Reset vote state and update session status
                        session.reset_end_session_vote()
                        # Note: We don't set status to 'completed' yet, wait for summary completion

                        # Broadcast end session approval
                        try:
                            broadcast_end_session_vote_update(session, request.user, 'session_ending')
                        except Exception as e:
                            pass

                        return Response({
                            'message': 'All participants voted. Moving to session summary.',
                            'session_ending': True,
                            'end_session_votes': session.end_session_votes,
                        }, status=status.HTTP_200_OK)
                    
                    return Response({
                        'message': 'Vote recorded successfully',
                        'end_session_votes': session.end_session_votes,
                        'vote_active': session.end_session_vote_active,
                        'vote_initiated_by': session.end_session_vote_initiated_by,
                        'vote_initiated_by_display': initiator_display_name,
                        'all_voted': all_voted,
                        'votes_count': len([v for v in session.end_session_votes.values() if v])
                    }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class SubmitSummaryResponse(APIView):
    """Submit 'how do you feel now' response for session summary"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, session_uuid):
        try:
            session = get_object_or_404(Session, session_uuid=session_uuid)
            
            # Check if user is a participant
            if not SessionParticipant.objects.filter(session=session, user=request.user).exists():
                return Response({'error': 'Not a participant in this session'}, status=status.HTTP_403_FORBIDDEN)
            
            how_you_feel_now = request.data.get('how_you_feel_now', '').strip()
            
            # Validation: at least 1 sentence (basic check for length)
            if len(how_you_feel_now) < 10:  # Rough check for at least one sentence
                return Response({'error': 'Please provide at least one sentence about how you feel now'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Create or update the summary response
            summary_response, created = SessionSummaryResponse.objects.update_or_create(
                session=session,
                user=request.user,
                defaults={'how_you_feel_now': how_you_feel_now}
            )
            
            # Check if all participants have submitted their responses
            participants = SessionParticipant.objects.filter(session=session)
            all_submitted = all(
                SessionSummaryResponse.objects.filter(session=session, user=participant.user).exists()
                for participant in participants
            )
            
            response_data = {
                'message': 'Response submitted successfully',
                'all_submitted': all_submitted,
            }
            
            # If all participants have submitted, generate AI summary ASYNCHRONOUSLY
            if all_submitted and not session.summary_generated:
                # Immediately notify users that summary generation is starting
                response_data['all_submitted'] = True
                response_data['summary_generating'] = True
                response_data['message'] = 'All responses submitted! AI is generating your session summary...'

                # Broadcast to all users that summary generation is starting
                try:
                    broadcast_session_summary_generating(session)
                except Exception as e:
                    pass

                # Generate AI summary asynchronously in background
                def generate_summary_async():
                    try:

                        # Ensure we have a fresh database connection in this thread
                        connection.close()

                        # Use atomic transaction to ensure data consistency
                        with transaction.atomic():
                            # Refresh session from database to ensure we have latest state
                            fresh_session = Session.objects.get(session_uuid=session.session_uuid)

                            # Generate the summary (this takes 3-5 seconds but doesn't block)
                            final_summary = self.generate_final_summary(fresh_session)

                            # Update session with generated summary and mark as completed
                            fresh_session.final_summary = final_summary
                            fresh_session.summary_generated = True
                            fresh_session.status = 'completed'
                            fresh_session.save()

                        # Broadcast summary completion to all participants (outside transaction)
                        # Get fresh session data for broadcast
                        fresh_session_for_broadcast = Session.objects.get(session_uuid=session.session_uuid)
                        broadcast_result = broadcast_session_summary_generated(fresh_session_for_broadcast)

                        # Broadcast session status change to update sidebar
                        try:
                            status_change_result = broadcast_session_status_change(fresh_session_for_broadcast, 'active', 'completed')
                        except Exception as e:
                            pass

                    except Exception as e:
                        traceback.print_exc()

                        # Refresh session for error broadcast
                        try:
                            # Ensure fresh database connection for error handling
                            connection.close()

                            fresh_session = Session.objects.get(session_uuid=session.session_uuid)
                            broadcast_session_summary_error(fresh_session, "Failed to generate summary. Please refresh the page.")
                        except Exception as broadcast_error:
                            pass

                # Start async summary generation
                thread = threading.Thread(target=generate_summary_async)
                thread.daemon = True
                thread.start()
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    def generate_final_summary(self, session):
        try:
            # Ensure both users have submitted their summary responses
            participants = SessionParticipant.objects.filter(session=session)
            summary_responses = SessionSummaryResponse.objects.filter(session=session).select_related('user')

            if summary_responses.count() != participants.count():
                raise ValueError("Not all participants have submitted their summary responses")

            return openrouter_service.generate_session_summary(session, summary_responses)
                
        except Exception as e:
            return "Unable to generate summary at this time. Thank you for your participation in this session."


class GetSessionSummary(APIView):
    """Get session summary data including responses and AI summary"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, session_uuid):
        try:
            session = get_object_or_404(Session, session_uuid=session_uuid)
            
            # Check if user is a participant
            if not SessionParticipant.objects.filter(session=session, user=request.user).exists():
                return Response({'error': 'Not a participant in this session'}, status=status.HTTP_403_FORBIDDEN)
            
            # Get all summary responses
            summary_responses = SessionSummaryResponse.objects.filter(session=session).select_related('user')
            responses_data = []
            for response in summary_responses:
                responses_data.append({
                    'user': response.user.display_name,
                    'how_you_feel_now': response.how_you_feel_now,
                    'submitted_at': response.submitted_at
                })
            
            # Check if current user has submitted
            user_has_submitted = SessionSummaryResponse.objects.filter(session=session, user=request.user).exists()
            
            # Check if all participants have submitted
            participants = SessionParticipant.objects.filter(session=session)
            all_submitted = all(
                SessionSummaryResponse.objects.filter(session=session, user=participant.user).exists()
                for participant in participants
            )
            
            return Response({
                'session_uuid': session.session_uuid,
                'initial_context': {
                    'categories': session.categories,
                    'context': session.context
                },
                'summary_responses': responses_data,
                'user_has_submitted': user_has_submitted,
                'all_submitted': all_submitted,
                'summary_generated': session.summary_generated,
                'final_summary': session.final_summary if session.summary_generated else None,
                'end_session_votes': session.end_session_votes or {},
                'end_session_vote_active': session.end_session_vote_active,
                'vote_initiated_by': session.end_session_vote_initiated_by
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class SSEView(APIView):
    """Server-Sent Events endpoint for real-time updates"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Check if request accepts text/event-stream
        accept_header = request.META.get('HTTP_ACCEPT', '')
        if 'text/event-stream' not in accept_header and 'text/plain' not in accept_header and '*/*' not in accept_header:
            return Response(
                {'error': 'This endpoint only supports text/event-stream'},
                status=status.HTTP_406_NOT_ACCEPTABLE
            )
        # Create event queue for this connection
        event_queue = []
        
        def event_stream():
            try:
                # Send initial connection event
                yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'user_id': request.user.id})}\n\n"
                
                # Keep connection alive and send queued events
                while True:
                    try:
                        # Send any queued events
                        if event_queue:
                            for event in event_queue:
                                yield event
                            event_queue.clear()
                        
                        # Send heartbeat every 30 seconds
                        yield f"event: heartbeat\ndata: {json.dumps({'timestamp': timezone.now().isoformat()})}\n\n"
                        time.sleep(30)

                    except GeneratorExit:
                        break
                    except Exception as e:
                        break

            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
            finally:
                # Clean up connection
                sse_manager.remove_connection(request.user.id)
        
        # Add connection to manager with event queue
        sse_manager.add_connection(request.user.id, event_queue)
        
        # Create streaming response
        response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
        response['Cache-Control'] = 'no-cache'
        response['Connection'] = 'keep-alive'
        # CORS headers are handled by corsheaders middleware in settings.py

        return response



class TestSSENotification(APIView):
    """Test endpoint to send SSE notifications"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Send test notification
            broadcast_notification(
                request.user.id,
                'Test Notification',
                'This is a test notification to verify SSE is working!',
                'info'
            )

            return Response({
                'message': 'Test notification sent successfully'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


class NgrokPrimeView(APIView):
    """Simple endpoint to help prime ngrok tunnel for SSE connections"""
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({
            'message': 'Ngrok tunnel primed successfully',
            'timestamp': timezone.now().isoformat(),
            'instructions': 'You can now establish SSE connections without the ngrok warning page'
        }, status=status.HTTP_200_OK)


@csrf_exempt
async def sse_stream(request):
    """Async SSE endpoint compatible with ASGI"""
    import logging
    logger = logging.getLogger(__name__)

    # Handle CORS preflight - CORS headers are handled by corsheaders middleware
    if request.method == 'OPTIONS':
        response = HttpResponse()
        # Let CORS middleware handle all CORS headers
        return response

    if request.method != 'GET':
        error_data = json.dumps({"error": "Method not allowed"})
        response = HttpResponse(f'event: error\ndata: {error_data}\n\n',
                              content_type='text/event-stream', status=405)
        response['Cache-Control'] = 'no-cache'
        return response

    # Get token from query parameter with better error handling
    token = request.GET.get('token')
    if not token:
        logger.error("SSE Stream: No token provided in query params")
        error_data = json.dumps({"error": "Token required in query parameter"})
        response = HttpResponse(f'event: error\ndata: {error_data}\n\n',
                              content_type='text/event-stream', status=401)
        response['Cache-Control'] = 'no-cache'
        return response

    # Validate token format - Firebase tokens are typically much longer
    if len(token) < 20:
        logger.error(f"SSE Stream: Token too short: {len(token)} characters")
        error_data = json.dumps({"error": "Invalid token format"})
        response = HttpResponse(f'event: error\ndata: {error_data}\n\n',
                              content_type='text/event-stream', status=401)
        response['Cache-Control'] = 'no-cache'
        return response

    logger.info(f"SSE Stream: Token received (length: {len(token)}): {token[:20]}...")

    try:
        # Verify the token with increased clock skew tolerance for network delays
        logger.info("SSE Stream: Attempting to verify Firebase token...")
        decoded_token = firebase_auth_admin.verify_id_token(token, clock_skew_seconds=60)
        uid = decoded_token.get('uid')

        # Check token expiration more explicitly
        exp = decoded_token.get('exp', 0)
        iat = decoded_token.get('iat', 0)
        current_time = time.time()

        if exp < current_time:
            logger.error(f"SSE Stream: Token expired. Exp: {exp}, Current: {current_time}, Diff: {current_time - exp}s")
            error_data = json.dumps({"error": "Token expired"})
            response = HttpResponse(f'event: error\ndata: {error_data}\n\n',
                                  content_type='text/event-stream', status=401)
            response['Cache-Control'] = 'no-cache'
            return response

        # Log token timing info for debugging
        logger.info(f"SSE Stream: Token timing - Issued: {iat}, Expires: {exp}, Current: {current_time}, TTL: {exp - current_time}s")
        logger.info(f"SSE Stream: Token verified successfully for UID: {uid}")

        # Get user (User model already imported at top of file)
        try:
            user = await User.objects.aget(username=uid)
            logger.info(f"SSE Stream: User found: {user.display_name} (ID: {user.id})")
        except User.DoesNotExist:
            logger.error(f"SSE Stream: User not found for UID: {uid}")
            error_data = json.dumps({"error": "User not found"})
            response = HttpResponse(f'event: error\ndata: {error_data}\n\n',
                                  content_type='text/event-stream', status=401)
            response['Cache-Control'] = 'no-cache'
            return response

    except Exception as e:
        logger.error(f"SSE Stream: Authentication failed: {str(e)}")
        import traceback
        logger.error(f"SSE Stream: Full traceback: {traceback.format_exc()}")

        # Provide more specific error messages for common issues
        error_str = str(e).lower()
        if 'expired' in error_str:
            error_msg = 'Token expired - please refresh your session'
        elif 'invalid' in error_str or 'malformed' in error_str:
            error_msg = 'Invalid token format'
        elif 'network' in error_str or 'timeout' in error_str:
            error_msg = 'Network error during authentication - please retry'
        else:
            error_msg = f'Authentication failed: {str(e)}'

        error_data = json.dumps({"error": error_msg})
        response = HttpResponse(f'event: error\ndata: {error_data}\n\n',
                              content_type='text/event-stream', status=401)
        response['Cache-Control'] = 'no-cache'
        return response
    
    # Create event queue for this connection
    event_queue = []
    
    async def event_stream():
        try:
            # Send initial connection event
            yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'user_id': user.id})}\n\n"
            
            # Keep connection alive and send queued events
            heartbeat_counter = 0
            while True:
                try:
                    # Send any queued events
                    if event_queue:
                        for event in event_queue:
                            yield event
                        event_queue.clear()
                    
                    # Send heartbeat every 30 iterations (approximately 30 seconds)
                    heartbeat_counter += 1
                    if heartbeat_counter >= 30:
                        yield f"event: heartbeat\ndata: {json.dumps({'timestamp': timezone.now().isoformat()})}\n\n"
                        heartbeat_counter = 0
                    
                    # Async sleep to not block the event loop
                    await asyncio.sleep(1)

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    break

        except Exception as e:
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
        finally:
            # Clean up connection
            sse_manager.remove_connection(user.id)
    
    # Add connection to manager with event queue
    sse_manager.add_connection(user.id, event_queue)
    
    # Create streaming response
    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    response['Connection'] = 'keep-alive'
    # CORS headers are handled by corsheaders middleware in settings.py

    logger.info(f"SSE Stream: Successfully created streaming response for user {user.id}")
    return response
