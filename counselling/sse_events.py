from typing import Dict, Any, List, Set
from django.contrib.auth import get_user_model
from .sse_manager import sse_manager
from .models import Session, SessionParticipant, RelationshipInvitation, SessionInvitation
import logging
from django.utils import timezone

User = get_user_model()
logger = logging.getLogger(__name__)

def broadcast_session_update(session, event_type: str = 'session_update', additional_data: Dict[str, Any] = None):
    """Broadcast session updates to all participants"""
    try:
        # Get all participants
        participants = SessionParticipant.objects.filter(session=session).select_related('user')
        user_ids = {p.user.id for p in participants}
        
        # Add session creator
        user_ids.add(session.creator.id)
        
        session_data = {
            'session_uuid': str(session.session_uuid),
            'status': session.status,
            'current_objective_index': session.current_objective_index,
            'objectives': session.objectives,
            'categories': session.categories,
            'created_at': session.created_at.isoformat(),
            'creator': session.creator.display_name,
        }
        
        if additional_data:
            session_data.update(additional_data)
        
        data = {
            'type': event_type,
            'session': session_data
        }
        
        # Broadcast to all participants
        results = sse_manager.broadcast_to_users(user_ids, event_type, data)
        logger.info(f"Broadcasted {event_type} to {len(user_ids)} users for session {session.session_uuid}")
        
        return results
    except Exception as e:
        logger.error(f"Error broadcasting session update: {e}")
        return {}


def broadcast_end_session_vote_update(session, user, vote_action: str):
    """Broadcast end session vote updates to all session participants"""
    try:
        # Get all participants
        participants = SessionParticipant.objects.filter(session=session).select_related('user')
        user_ids = {p.user.id for p in participants}
        
        # Add session creator
        user_ids.add(session.creator.id)
        
        # Get initiator display name
        initiator_display_name = user.display_name
        if session.end_session_vote_initiated_by and session.end_session_vote_initiated_by != user.username:
            try:
                initiator_user = User.objects.get(username=session.end_session_vote_initiated_by)
                initiator_display_name = initiator_user.display_name
            except User.DoesNotExist:
                initiator_display_name = session.end_session_vote_initiated_by
        
        vote_data = {
            'session_uuid': str(session.session_uuid),
            'vote_action': vote_action,
            'vote_active': session.end_session_vote_active,
            'vote_initiated_by': session.end_session_vote_initiated_by,
            'vote_initiated_by_display': initiator_display_name,
            'end_session_votes': session.end_session_votes or {},
            'votes_count': len([v for v in (session.end_session_votes or {}).values() if v]),
            'voter_display_name': user.display_name,
            'voter_username': user.username,
        }
        
        data = {
            'type': 'end_session_vote_update',
            'vote_data': vote_data
        }
        
        # Broadcast to all participants
        results = sse_manager.broadcast_to_users(user_ids, 'end_session_vote_update', data)
        logger.info(f"Broadcasted end session vote update ({vote_action}) to {len(user_ids)} users for session {session.session_uuid}")
        
        return results
    except Exception as e:
        logger.error(f"Error broadcasting end session vote update: {e}")
        return {}

def broadcast_objective_completion(session, objective_index):
    """Broadcast that an objective has been completed to all session participants"""
    try:
        # Get all participants
        participants = SessionParticipant.objects.filter(session=session).select_related('user')
        user_ids = {p.user.id for p in participants}

        # Add session creator
        user_ids.add(session.creator.id)

        completion_data = {
            'session_uuid': str(session.session_uuid),
            'objective_index': objective_index,
            'objective_text': session.objectives[objective_index] if objective_index < len(session.objectives) else '',
            'current_objective_index': session.current_objective_index,
            'total_objectives': len(session.objectives),
            'completed_objectives': session.current_objective_index + 1,  # Since we just completed this objective
        }

        data = {
            'type': 'objective_completion',
            'completion_data': completion_data
        }

        # Broadcast to all participants
        results = sse_manager.broadcast_to_users(user_ids, 'objective_completion', data)
        logger.info(f"Broadcasted objective completion (objective {objective_index}) to {len(user_ids)} users for session {session.session_uuid}")

        return results
    except Exception as e:
        logger.error(f"Error broadcasting objective completion: {e}")
        return {}


def broadcast_session_summary_generated(session):
    """Broadcast that session summary has been generated to all participants"""
    try:
        # Get all participants
        participants = SessionParticipant.objects.filter(session=session).select_related('user')
        user_ids = {p.user.id for p in participants}

        # Add session creator
        user_ids.add(session.creator.id)

        data = {
            'type': 'session_summary_generated',
            'session_uuid': str(session.session_uuid),
            'final_summary': session.final_summary
        }

        # Broadcast to all participants
        results = sse_manager.broadcast_to_users(user_ids, 'session_summary_generated', data)
        logger.info(f"Broadcasted session summary generated to {len(user_ids)} users for session {session.session_uuid}")

        return results
    except Exception as e:
        logger.error(f"Error broadcasting session summary generated: {e}")
        import traceback
        traceback.print_exc()
        return {}

def broadcast_session_summary_generating(session):
    """Broadcast that session summary generation is starting to all participants"""
    try:
        # Get all participants
        participants = SessionParticipant.objects.filter(session=session).select_related('user')
        user_ids = {p.user.id for p in participants}

        # Add session creator
        user_ids.add(session.creator.id)

        data = {
            'type': 'session_summary_generating',
            'session_uuid': str(session.session_uuid),
            'message': 'All responses submitted! AI is generating your session summary...'
        }

        # Broadcast to all participants
        results = sse_manager.broadcast_to_users(user_ids, 'session_summary_generating', data)
        logger.info(f"Broadcasted session summary generating to {len(user_ids)} users for session {session.session_uuid}")

        return results
    except Exception as e:
        logger.error(f"Error broadcasting session summary generating: {e}")
        return {}

def broadcast_session_summary_error(session, error_message):
    """Broadcast that session summary generation failed to all participants"""
    try:
        # Get all participants
        participants = SessionParticipant.objects.filter(session=session).select_related('user')
        user_ids = {p.user.id for p in participants}

        # Add session creator
        user_ids.add(session.creator.id)

        data = {
            'type': 'session_summary_error',
            'session_uuid': str(session.session_uuid),
            'error_message': error_message
        }

        # Broadcast to all participants
        results = sse_manager.broadcast_to_users(user_ids, 'session_summary_error', data)
        logger.info(f"Broadcasted session summary error to {len(user_ids)} users for session {session.session_uuid}")

        return results
    except Exception as e:
        logger.error(f"Error broadcasting session summary error: {e}")
        return {}

def broadcast_session_invitation(invitation, event_type: str = 'session_invitation'):
    """Broadcast session invitation to the invited user"""
    try:
        invitation_data = {
            'invitation_uuid': str(invitation.invitation_uuid),
            'session_uuid': str(invitation.session.session_uuid),
            'from_user': invitation.from_user.display_name,
            'from_user_id': invitation.from_user.id,
            'message': invitation.message,
            'created_at': invitation.created_at.isoformat(),
            'expires_at': invitation.expires_at.isoformat(),
            'categories': invitation.session.categories,
            'status': invitation.status,
        }
        
        data = {
            'type': event_type,
            'invitation': invitation_data
        }
        
        # Broadcast to invited user
        success = sse_manager.broadcast_to_user(invitation.to_user.id, event_type, data)
        logger.info(f"Broadcasted session invitation to user {invitation.to_user.id}")

        return success
    except Exception as e:
        logger.error(f"Error broadcasting session invitation: {e}")
        return False

def broadcast_relationship_invitation(invitation, event_type: str = 'relationship_invitation'):
    """Broadcast relationship invitation to the invited user"""
    try:
        invitation_data = {
            'invitation_uuid': str(invitation.invitation_uuid),
            'from_user': invitation.from_user.display_name,
            'from_user_id': invitation.from_user.id,
            'to_email': invitation.to_email,
            'relationship_type': invitation.relationship_type,
            'relationship_type_display': invitation.get_relationship_type_display(),
            'message': invitation.message,
            'created_at': invitation.created_at.isoformat(),
            'expires_at': invitation.expires_at.isoformat(),
            'status': invitation.status,
        }
        
        data = {
            'type': event_type,
            'invitation': invitation_data
        }
        
        # Broadcast to invited user if they exist
        if invitation.to_user:
            success = sse_manager.broadcast_to_user(invitation.to_user.id, event_type, data)
            logger.info(f"Broadcasted relationship invitation to user {invitation.to_user.id}")
            return success
        else:
            logger.info(f"Relationship invitation sent to {invitation.to_email} but user doesn't exist yet")
            return False
    except Exception as e:
        logger.error(f"Error broadcasting relationship invitation: {e}")
        return False

def broadcast_session_status_change(session, old_status: str, new_status: str):
    """Broadcast session status changes"""
    return broadcast_session_update(
        session, 
        event_type='session_status_change',
        additional_data={
            'old_status': old_status,
            'new_status': new_status
        }
    )

def broadcast_objective_advancement(session, old_objective_index: int, new_objective_index: int):
    """Broadcast objective advancement to participants"""
    return broadcast_session_update(
        session,
        event_type='objective_advancement',
        additional_data={
            'old_objective_index': old_objective_index,
            'new_objective_index': new_objective_index,
            'current_objective': session.objectives[new_objective_index] if new_objective_index < len(session.objectives) else None
        }
    )



def broadcast_notification(user_id: int, title: str, message: str, notification_type: str = 'info'):
    """Broadcast a general notification to a user"""
    try:
        data = {
            'type': 'notification',
            'notification': {
                'title': title,
                'message': message,
                'type': notification_type,
                'timestamp': timezone.now().isoformat()
            }
        }
        
        success = sse_manager.broadcast_to_user(user_id, 'notification', data)
        logger.info(f"Broadcasted notification to user {user_id}: {title}")
        
        return success
    except Exception as e:
        logger.error(f"Error broadcasting notification: {e}")
        return False

def broadcast_user_sessions_update(user_id: int, sessions_data: List[Dict[str, Any]]):
    """Broadcast updated sessions list to a user"""
    try:
        data = {
            'type': 'sessions_update',
            'sessions': sessions_data
        }
        
        success = sse_manager.broadcast_to_user(user_id, 'sessions_update', data)
        logger.info(f"Broadcasted sessions update to user {user_id}")
        
        return success
    except Exception as e:
        logger.error(f"Error broadcasting sessions update: {e}")
        return False

def broadcast_vote_update(session, objective_room, user, vote_action: str):
    """Broadcast vote updates to all session participants"""
    try:
        # Get all participants
        participants = SessionParticipant.objects.filter(session=session).select_related('user')
        user_ids = {p.user.id for p in participants}
        
        # Add session creator
        user_ids.add(session.creator.id)
        
        # Get initiator display name
        initiator_display_name = user.display_name
        if objective_room.vote_initiated_by and objective_room.vote_initiated_by != user.username:
            try:
                initiator_user = User.objects.get(username=objective_room.vote_initiated_by)
                initiator_display_name = initiator_user.display_name
            except User.DoesNotExist:
                initiator_display_name = objective_room.vote_initiated_by
        
        vote_data = {
            'session_uuid': str(session.session_uuid),
            'objective_index': objective_room.objective_index,
            'vote_action': vote_action,
            'vote_active': objective_room.vote_active,
            'vote_initiated_by': objective_room.vote_initiated_by,
            'vote_initiated_by_display': initiator_display_name,
            'move_to_next_votes': objective_room.move_to_next_votes or {},
            'votes_count': len([v for v in (objective_room.move_to_next_votes or {}).values() if v]),
            'voter_display_name': user.display_name,
            'voter_username': user.username,
        }
        
        data = {
            'type': 'vote_update',
            'vote_data': vote_data
        }
        
        # Broadcast to all participants
        results = sse_manager.broadcast_to_users(user_ids, 'vote_update', data)
        logger.info(f"Broadcasted vote update ({vote_action}) to {len(user_ids)} users for session {session.session_uuid}")
        
        return results
    except Exception as e:
        logger.error(f"Error broadcasting vote update: {e}")
        return {}

def broadcast_objective_transition(session, old_objective_index: int, new_objective_index: int):
    """Broadcast objective transition to all session participants"""
    try:
        # Get all participants
        participants = SessionParticipant.objects.filter(session=session).select_related('user')
        user_ids = {p.user.id for p in participants}

        # Add session creator
        user_ids.add(session.creator.id)

        transition_data = {
            'session_uuid': str(session.session_uuid),
            'old_objective_index': old_objective_index,
            'new_objective_index': new_objective_index,
            'current_objective_index': session.current_objective_index,
            'old_objective_text': session.objectives[old_objective_index] if old_objective_index < len(session.objectives) else '',
            'new_objective_text': session.objectives[new_objective_index] if new_objective_index < len(session.objectives) else '',
            'objectives': session.objectives,
            'transition_type': 'objective_completed'
        }

        data = {
            'type': 'objective_transition',
            'transition_data': transition_data
        }

        # Broadcast to all participants
        results = sse_manager.broadcast_to_users(user_ids, 'objective_transition', data)
        logger.info(f"Broadcasted objective transition ({old_objective_index} -> {new_objective_index}) to {len(user_ids)} users for session {session.session_uuid}")

        return results
    except Exception as e:
        logger.error(f"Error broadcasting objective transition: {e}")
        return {}

def broadcast_objective_transition_with_message(session, old_objective_index: int, new_objective_index: int, ai_message_content: str):
    """Broadcast objective transition with AI message to all session participants"""
    try:
        # Get all participants
        participants = SessionParticipant.objects.filter(session=session).select_related('user')
        user_ids = {p.user.id for p in participants}

        # Add session creator
        user_ids.add(session.creator.id)

        transition_data = {
            'session_uuid': str(session.session_uuid),
            'old_objective_index': old_objective_index,
            'new_objective_index': new_objective_index,
            'current_objective_index': session.current_objective_index,
            'old_objective_text': session.objectives[old_objective_index] if old_objective_index < len(session.objectives) else '',
            'new_objective_text': session.objectives[new_objective_index] if new_objective_index < len(session.objectives) else '',
            'objectives': session.objectives,
            'transition_type': 'objective_completed',
            'ai_message': {
                'content': ai_message_content,
                'sender': {
                    'uid': 'llm',
                    'name': 'AI Counselor'
                }
            }
        }

        data = {
            'type': 'objective_transition',
            'transition_data': transition_data
        }

        # Broadcast to all participants
        results = sse_manager.broadcast_to_users(user_ids, 'objective_transition', data)
        logger.info(f"Broadcasted objective transition with AI message ({old_objective_index} -> {new_objective_index}) to {len(user_ids)} users for session {session.session_uuid}")

        return results
    except Exception as e:
        logger.error(f"Error broadcasting objective transition with message: {e}")
        return {}

def broadcast_session_completion(session):
    """Broadcast session completion to all participants"""
    try:
        # Get all participants
        participants = SessionParticipant.objects.filter(session=session).select_related('user')
        user_ids = {p.user.id for p in participants}
        
        # Add session creator
        user_ids.add(session.creator.id)
        
        completion_data = {
            'session_uuid': str(session.session_uuid),
            'message': 'Congratulations! You have completed all session objectives.',
            'total_objectives': len(session.objectives),
            'objectives': session.objectives,
            'session_status': 'completed'
        }
        
        data = {
            'type': 'session_completion',
            'completion_data': completion_data
        }
        
        # Broadcast to all participants
        results = sse_manager.broadcast_to_users(user_ids, 'session_completion', data)
        logger.info(f"Broadcasted session completion to {len(user_ids)} users for session {session.session_uuid}")
        
        return results
    except Exception as e:
        logger.error(f"Error broadcasting session completion: {e}")
        return {} 