import json
import threading
import traceback

from asgiref.sync import async_to_sync
from channels.generic.websocket import WebsocketConsumer
from channels.layers import get_channel_layer
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction

from .models import LLMResponse, Message, Reflection, Round, Session, SessionParticipant, ObjectiveRoom
from .openrouter_service import openrouter_service
from .sse_events import broadcast_objective_transition

User = get_user_model()

# Global connection tracking to prevent duplicate connections
active_connections = {}

def get_or_create_active_round(session, objective_room=None):
    """Get or create an active round for the session and objective room"""
    
    # If objective_room is provided, filter by it
    if objective_room:
        last_round = (
            objective_room.rounds.
            select_related("llm_response")
            .order_by('-round_index')
            .first()
        )
    else:
        # Fallback to session-level rounds (for backward compatibility)
        last_round = (
            session.rounds.
            select_related("llm_response")
            .order_by('-round_index')
            .first()
        )

    answered = False
    if last_round is not None:
        try:
            _ = last_round.llm_response   # will raise if missing
            answered = True
        except ObjectDoesNotExist:
            answered = False
        
    if last_round is None or answered:
        with transaction.atomic():
            next_idx = Round.get_max_round_index(session.session_uuid, objective_room) + 1
            last_round = Round.objects.create(
                session=session,
                objective_room=objective_room,
                round_index=next_idx
            )
    return last_round

def can_user_send_message(user, chat_round):
    """
    Check if a user can send a message in the current round.
    """
    if Message.objects.filter(chat_round=chat_round, sender=user).exists():
        return False, "You have already sent a message in this round. Wait for your partner and the AI to respond."
    return True, ""

def call_llm_api(chat_round):
    """
    Call the LLM API with session context and chat history.
    """
    try:
        session = chat_round.session
        reflections = Reflection.objects.filter(session=session).select_related('user')

        # Get reflections from both participants
        participants_reflections = []
        for reflection in reflections:
            participants_reflections.append({
                'display_name': reflection.user.display_name,
                'feelings': reflection.feelings,
                'expected_outcome': reflection.expected_outcome
            })

        # Build chat history using display_name for readability
        all_messages = []
        rounds = session.rounds.prefetch_related('messages__sender', 'llm_response').order_by('round_index')
        for round_obj in rounds:
            messages = round_obj.messages.order_by('sent_at')
            for message in messages:
                all_messages.append(f"{message.sender.display_name}: {message.content}")

            if round_obj != chat_round and hasattr(round_obj, 'llm_response'):
                try:
                    all_messages.append(f"Counselor: {round_obj.llm_response.content}")
                except ObjectDoesNotExist:
                    pass

        conversation_summary = "\n".join(all_messages) or "This is the beginning of the conversation."
        
        return openrouter_service.generate_conversation_response(session, conversation_summary)
    except Exception as e:
        return "I apologize, but I'm having trouble generating a response right now. Please continue your conversation."

def call_initial_llm_api(session):
    """
    Call the LLM API for the initial session greeting.
    """
    try:
        reflections = Reflection.objects.filter(session=session).select_related('user')
        if reflections.count() < 2:
            return "Welcome! Let's begin once both participants are ready."

        participants_info = []
        for reflection in reflections:
            participants_info.append(f"{reflection.user.display_name} shared that they feel: \"{reflection.feelings}\" and hope to achieve: \"{reflection.expected_outcome}\"")

        return openrouter_service.generate_session_greeting(session, participants_info)
    except Exception as e:
        print(e)
        return "Welcome to your counseling session! I'm here to help guide your conversation. Please feel free to share your thoughts and feelings openly."

def generate_initial_llm_response(session_uuid):
    try:
        session = Session.objects.get(session_uuid=session_uuid)

        # This function generates the session-level initial greeting
        # It's different from objective-specific messages

        chat_round = get_or_create_active_round(session)

        # Check if session-level initial greeting already exists
        if LLMResponse.objects.filter(chat_round=chat_round).exists():
            return

        channel_layer = get_channel_layer()

        # Note: Typing indicator is now handled by frontend when no messages exist

        llm_text = call_initial_llm_api(session)

        LLMResponse.objects.create(chat_round=chat_round, content=llm_text)

        # Note: Typing indicator stop is now handled by frontend when message arrives

        async_to_sync(channel_layer.group_send)(
            f"{session_uuid}_session",
            {
                "type":   "chat_message",
                "sender": { "uid": "llm", "name": "AI Counselor" },
                "content": llm_text,
            },
        )

        # Broadcast turn state updates
        participants = SessionParticipant.objects.filter(session=session).select_related('user')
        for participant in participants:
            turn_state = get_session_turn_state(session, participant.user)
            async_to_sync(channel_layer.group_send)(
                f"{session_uuid}_session",
                {
                    'type': 'turn_state_update',
                    'user': participant.user.username,
                    'turn_state': turn_state
                }
            )

    except Exception as e:
        pass
        # Stop typing indicator on error
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"{session_uuid}_session",
                {
                    "type": "llm_typing_stop",
                },
            )
        except:
            pass

def run_llm_in_background(chat_round):
    try:
        llm_text = call_llm_api(chat_round)
        LLMResponse.objects.create(chat_round=chat_round, content=llm_text)

        channel_layer = get_channel_layer()
        # Stop typing indicator
        async_to_sync(channel_layer.group_send)(
            f"{chat_round.session.session_uuid}_session",
            {
                "type": "llm_typing_stop",
            },
        )

        async_to_sync(channel_layer.group_send)(
            f"{chat_round.session.session_uuid}_session",
            {
                "type":   "chat_message",
                "sender": { "uid": "llm", "name": "AI Counselor" },
                "content": llm_text,
            },
        )

        # Check if message limit (100) has been reached
        if chat_round.objective_room:
            # Count all messages in this objective room (including LLM responses)
            message_count = sum(
                round_obj.messages.count() + (1 if hasattr(round_obj, 'llm_response') else 0)
                for round_obj in chat_round.objective_room.rounds.all()
            )
            
            if message_count >= 100:
                # Auto-advance to next objective
                try:
                    # Mark current objective as completed
                    chat_round.objective_room.status = 'completed'
                    chat_round.objective_room.save()
                    
                    # Move to next objective
                    next_objective_index = chat_round.session.current_objective_index + 1
                    if next_objective_index < len(chat_round.session.objectives):
                        chat_round.session.current_objective_index = next_objective_index
                        chat_round.session.save()
                        
                        # Create or activate next objective room
                        next_objective_room, created = ObjectiveRoom.objects.get_or_create(
                            session=chat_round.session,
                            objective_index=next_objective_index,
                            defaults={
                                'objective_text': chat_round.session.objectives[next_objective_index],
                                'status': 'active'
                            }
                        )
                        
                        # Note: Initial AI message for new objective will be generated when users connect
                        
                        # Send message limit reached notification
                        async_to_sync(channel_layer.group_send)(
                            f"{chat_round.session.session_uuid}_session",
                            {
                                'type': 'message_limit_reached',
                                'message': 'Message limit reached! Moving to next objective...',
                                'objective_index': chat_round.objective_room.objective_index,
                                'next_objective_index': next_objective_index
                            }
                        )
                    else:
                        # Session completed
                        chat_round.session.status = 'completed'
                        chat_round.session.save()
                        
                        async_to_sync(channel_layer.group_send)(
                            f"{chat_round.session.session_uuid}_session",
                            {
                                'type': 'session_completed',
                                'message': 'Congratulations! You have completed all objectives.'
                            }
                        )
                        
                except Exception as e:
                    pass

        # Broadcast turn state updates
        participants = SessionParticipant.objects.filter(session=chat_round.session).select_related('user')
        for participant in participants:
            turn_state = get_session_turn_state(chat_round.session, participant.user, chat_round.objective_room)
            async_to_sync(channel_layer.group_send)(
                f"{chat_round.session.session_uuid}_session",
                {
                    'type': 'turn_state_update',
                    'user': participant.user.username,
                    'turn_state': turn_state
                }
            )
    except Exception as e:
        # Stop typing indicator on error
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"{chat_round.session.session_uuid}_session",
            {
                "type": "llm_typing_stop",
            },
        )

def maybe_run_llm(chat_round):
    if LLMResponse.objects.filter(chat_round=chat_round).exists():
        return

    distinct_senders = (
        chat_round.messages
        .values_list("sender_id", flat=True)
        .distinct()
        .count()
    )

    if distinct_senders < 2:
        return

    # Show typing indicator
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"{chat_round.session.session_uuid}_session",
        {
            "type": "llm_typing_start",
            "message": "AI Counselor is thinking..."
        },
    )

    thread = threading.Thread(
        target=run_llm_in_background,
        args=(chat_round,)
    )
    thread.daemon = True
    thread.start()

def get_session_turn_state(session, user, objective_room=None):
    # Check if session is read-only first
    if session.is_read_only():
        return {
            'can_send': False,
            'status': 'read_only',
            'waiting_for': [],
            'round_index': 0,
            'messages_in_round': 0
        }

    current_round = get_or_create_active_round(session, objective_room)
    messages_in_round = Message.objects.filter(chat_round=current_round).select_related('sender')

    user_has_spoken = messages_in_round.filter(sender=user).exists()
    participants = SessionParticipant.objects.filter(session=session).select_related('user')
    participant_uids = {p.user.username for p in participants}
    messages_by_uid = {msg.sender.username for msg in messages_in_round}

    total_messages_count = messages_in_round.count()
    is_session_creator = session.creator == user
    waiting_for_uids = []  # Use a consistent list for UIDs

    if current_round.round_index == 1 and total_messages_count == 0:
        if is_session_creator:
            can_send = True
            status = "your_turn"
        else:
            can_send = False
            status = "waiting_for_partner"
            # FIXED: Add the UID to the waiting list
            waiting_for_uids = [session.creator.username]
    elif not user_has_spoken:
        if total_messages_count == 0:
            can_send = True
            status = "your_turn"
        else:
            others_spoken = all(uid in messages_by_uid
                              for uid in participant_uids
                              if uid != user.username)

            if others_spoken:
                can_send = True
                status = "your_turn"
            else:
                can_send = False
                status = "waiting_for_partner"
                waiting_for_uids = [uid for uid in participant_uids
                                   if uid != user.username and uid not in messages_by_uid]
    else:
        can_send = False
        # This correctly builds the list of waiting UIDs
        waiting_for_uids = [uid for uid in participant_uids if uid != user.username and uid not in messages_by_uid]

        if waiting_for_uids:
            status = "waiting_for_partner"
        elif not LLMResponse.objects.filter(chat_round=current_round).exists():
            status = "waiting_for_ai"
            # Use a special key for the AI, not a UID
            waiting_for_uids = ["AI Counselor"]
        else:
            status = "ready_for_new_round"

    # Convert waiting UIDs to display names for the frontend
    uid_to_display_name = {p.user.username: p.user.display_name for p in participants}
    waiting_for_names = [uid_to_display_name.get(uid, "Partner") for uid in waiting_for_uids if uid != "AI Counselor"]
    if "AI Counselor" in waiting_for_uids:
        waiting_for_names.append("AI Counselor")

    return {
        'can_send': can_send,
        'status': status,
        'waiting_for': waiting_for_names,
        'round_index': current_round.round_index,
        'messages_in_round': total_messages_count
    }

def generate_initial_objective_message(session, objective_room):
    """
    Generate initial AI message for an objective room
    """
    try:
        return openrouter_service.generate_objective_introduction(session, objective_room)
    except Exception as e:
        objective_number = objective_room.objective_index + 1
        return f"Welcome to objective {objective_number}! Let's focus on: {objective_room.objective_text}. How are you both feeling about working on this together?"

def generate_transition_ai_message(session, objective_room):
    """
    Generate AI message specifically for objective transitions.
    Always generates a fresh message regardless of existing content.
    """
    try:
        # Get the next round index for this objective room
        existing_rounds_count = Round.objects.filter(objective_room=objective_room).count()
        next_round_index = existing_rounds_count + 1

        # Create new round for the transition AI message
        transition_round = Round.objects.create(
            session=session,
            objective_room=objective_room,
            round_index=next_round_index
        )

        # Generate fresh AI message for the transition
        transition_message = generate_initial_objective_message(session, objective_room)

        # Create LLM response
        llm_response = LLMResponse.objects.create(
            chat_round=transition_round,
            content=transition_message
        )

        # Broadcast the transition message (using same format as normal messages)
        channel_layer = get_channel_layer()

        broadcast_data = {
            "type": "chat_message",
            "content": transition_message,
            "sender": {
                "uid": "llm",
                "name": "AI Counselor"
            }
        }

        async_to_sync(channel_layer.group_send)(
            f"{session.session_uuid}_session",
            broadcast_data
        )

    except Exception as e:
        traceback.print_exc()
        raise

def generate_transition_ai_message_sync(session, objective_room):
    """
    Generate AI message specifically for objective transitions SYNCHRONOUSLY.
    Returns the message content instead of broadcasting it.
    This ensures the message is ready before the SSE transition event is sent.
    """
    try:
        # Get the next round index for this objective room
        existing_rounds_count = Round.objects.filter(objective_room=objective_room).count()
        next_round_index = existing_rounds_count + 1

        # Create new round for the transition AI message
        transition_round = Round.objects.create(
            session=session,
            objective_room=objective_room,
            round_index=next_round_index
        )

        # Generate fresh AI message for the transition
        transition_message = generate_initial_objective_message(session, objective_room)

        # Create LLM response
        llm_response = LLMResponse.objects.create(
            chat_round=transition_round,
            content=transition_message
        )

        return transition_message

    except Exception as e:
        traceback.print_exc()
        raise

# Note: maybe_generate_initial_objective_message function removed
# Initial messages are now generated when session becomes active via generate_initial_llm_response

# Make a unique room
# connect specific people to the room (that might be clients job)
    # ->  TODO (!!) so what we need is validation -> accept and assign if right user, otherwise close connection
class ChatConsumer(WebsocketConsumer):
    def connect(self):
        """
        Handles new WebSocket connections.
        Session-wide connections that can handle any objective.
        """
        self.room_name = self.scope["url_route"]["kwargs"]["session_uuid"]
        self.objective_index = self.scope["url_route"]["kwargs"].get("objective_index", None)  # Optional for backward compatibility
        self.room_group_name = f'{self.room_name}_session'
        self.user_id = None  # Will be set during identification
        self.connection_key = None  # Will be set during identification
        self.current_objective_index = None  # Will be set during message handling

        # Add to group immediately
        async_to_sync(self.channel_layer.group_add)(
            self.room_group_name,
            self.channel_name
        )
        self.accept()

    def disconnect(self, close_code):
        """
        Handles WebSocket disconnections and cleanup.
        """
        # Remove from room group
        async_to_sync(self.channel_layer.group_discard)(
            self.room_group_name,
            self.channel_name
        )

        # Clean up connection tracking
        if hasattr(self, 'connection_key') and self.connection_key:
            if self.connection_key in active_connections:
                if active_connections[self.connection_key] == self.channel_name:
                    del active_connections[self.connection_key]

    def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message_type = text_data_json.get('type', 'message')
        username = text_data_json.get('username')
        objective_index = text_data_json.get('objective_index', self.objective_index)
        

        
        if message_type == 'identify':
            try:
                session = Session.objects.get(session_uuid=self.room_name)
                user = User.objects.get(username=username)

                # Track user ID for this connection
                self.user_id = user.id
                self.connection_key = f"{user.id}_{self.room_name}"
                self.current_objective_index = objective_index

                # Simple connection tracking - just register this connection
                # Remove aggressive connection closing to prevent instability
                if self.connection_key in active_connections:
                    old_channel = active_connections[self.connection_key]
                    if old_channel == self.channel_name:
                        return

                # Register this connection as the active one for this user/session
                active_connections[self.connection_key] = self.channel_name

                # Get or create objective room for the current session objective
                # Use session's current objective index, not the one from URL (which may be outdated)
                current_objective_index = session.current_objective_index
                objective_room = None
                try:
                    objective_room = ObjectiveRoom.objects.get(
                        session=session,
                        objective_index=current_objective_index
                    )
                except ObjectiveRoom.DoesNotExist:
                    if current_objective_index < len(session.objectives):
                        objective_room = ObjectiveRoom.objects.create(
                            session=session,
                            objective_index=current_objective_index,
                            objective_text=session.objectives[current_objective_index],
                            status='active'
                        )

                # Note: Initial AI messages are now generated when session becomes active
                # Typing indicators are handled by frontend based on message state

                turn_state = get_session_turn_state(session, user, objective_room)

                self.send(text_data=json.dumps({
                    'type': 'turn_state',
                    'user': username,
                    'turn_state': turn_state
                }))
            except Session.DoesNotExist:
                self.send(text_data=json.dumps({'type': 'error', 'message': 'Session does not exist'}))
            except User.DoesNotExist:
                self.send(text_data=json.dumps({'type': 'error', 'message': 'User does not exist'}))
            except IndexError:
                self.send(text_data=json.dumps({'type': 'error', 'message': 'Invalid objective index'}))
            return

        try:
            sender = User.objects.get(username=username)
            session = Session.objects.get(session_uuid=self.room_name)
            
            # Get or create objective room
            objective_room, created = ObjectiveRoom.objects.get_or_create(
                session=session,
                objective_index=objective_index,
                defaults={
                    'objective_text': session.objectives[objective_index] if objective_index < len(session.objectives) else '',
                    'status': 'active' if objective_index == session.current_objective_index else 'locked'
                }
            )
            
            # Check if session is read-only (completed or rejected)
            if session.is_read_only():
                self.send(text_data=json.dumps({
                    'type': 'error',
                    'message': 'This session is read-only. No new messages can be sent.',
                    'turn_state': get_session_turn_state(session, sender, objective_room)
                }))
                return

            # Check if user can access this objective
            if objective_index > session.current_objective_index:
                self.send(text_data=json.dumps({
                    'type': 'error',
                    'message': 'This objective is locked. Complete previous objectives first.',
                    'turn_state': get_session_turn_state(session, sender, objective_room)
                }))
                return

            chat_round = get_or_create_active_round(session, objective_room)

            can_send, reason = can_user_send_message(sender, chat_round)
            if not can_send:
                self.send(text_data=json.dumps({
                    'type': 'error',
                    'message': reason,
                    'turn_state': get_session_turn_state(session, sender, objective_room)
                }))
                return

            message = Message.objects.create(
                chat_round=chat_round,
                sender=sender,
                content=text_data_json.get('message')
            )

            # Count messages in this objective room
            message_count = sum(
                round_obj.messages.count() 
                for round_obj in objective_room.rounds.all()
            )
            
            # Check if message limit (100) has been reached
            if message_count >= 100:
                # Auto-advance to next objective
                self.auto_advance_to_next_objective(session, objective_room)
                
                # Send message limit reached notification
                async_to_sync(self.channel_layer.group_send)(
                    self.room_group_name,
                    {
                        'type': 'message_limit_reached',
                        'message': 'Message limit reached! Moving to next objective...',
                        'objective_index': objective_index,
                        'next_objective_index': session.current_objective_index
                    }
                )
            else:
                # Normal message broadcast
                async_to_sync(self.channel_layer.group_send)(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'content': message.content,
                        'sender': {
                            'uid': sender.username,
                            'name': sender.display_name
                        }
                    }
                )

            self.broadcast_turn_state(session, objective_room)
            maybe_run_llm(chat_round)

        except (User.DoesNotExist, Session.DoesNotExist):
            self.send(text_data=json.dumps({'type': 'error', 'message': 'Invalid user or session'}))
        except Exception as e:
            self.send(text_data=json.dumps({'type': 'error', 'message': f'An error occurred: {str(e)}'}))

    def auto_advance_to_next_objective(self, session, current_objective_room):
        """Auto-advance to the next objective when message limit is reached"""
        # Mark current objective as completed
        current_objective_room.status = 'completed'
        current_objective_room.save()

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

            # Broadcast transition immediately (for speed)
            broadcast_objective_transition(
                session,
                old_objective_index,
                session.current_objective_index
            )

            # Generate AI message asynchronously
            def generate_ai_async():
                try:
                    # Show typing indicator for objective transition
                    async_to_sync(self.channel_layer.group_send)(
                        f"{session.session_uuid}_session",
                        {
                            "type": "llm_typing_start",
                            "message": f"AI Counselor is joining objective {next_objective_index + 1}..."
                        }
                    )

                    # Generate message
                    ai_message = generate_transition_ai_message_sync(session, next_objective_room)

                    # Stop typing and send message
                    async_to_sync(self.channel_layer.group_send)(
                        f"{session.session_uuid}_session",
                        {"type": "llm_typing_stop"}
                    )
                    async_to_sync(self.channel_layer.group_send)(
                        f"{session.session_uuid}_session",
                        {
                            "type": "chat_message",
                            "sender": {"uid": "llm", "name": "AI Counselor"},
                            "content": ai_message
                        }
                    )
                    print(f"Auto-advance: Async AI message generated for objective {next_objective_index}")

                except Exception as e:
                    print(f"Auto-advance: Async AI generation failed: {e}")
                    # Send fallback message
                    try:
                        objective_number = next_objective_room.objective_index + 1
                        fallback_message = f"Welcome to objective {objective_number}! Let's focus on: {next_objective_room.objective_text}. How are you both feeling about working on this together?"

                        async_to_sync(self.channel_layer.group_send)(
                            f"{session.session_uuid}_session",
                            {"type": "llm_typing_stop"}
                        )
                        async_to_sync(self.channel_layer.group_send)(
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

        else:
            # Session completed
            session.status = 'completed'
            session.save()

    def broadcast_turn_state(self, session, objective_room=None):
        participants = SessionParticipant.objects.filter(session=session).select_related('user')
        for participant in participants:
            turn_state = get_session_turn_state(session, participant.user, objective_room)
            async_to_sync(self.channel_layer.group_send)(
                self.room_group_name,
                {
                    'type': 'turn_state_update',
                    'user': participant.user.username,
                    'turn_state': turn_state
                }
            )

    def chat_message(self, event):
        self.send(text_data=json.dumps({
            'type': 'chat',
            'content': event['content'],
            'sender': event['sender']
        }))

    def turn_state_update(self, event):
        self.send(text_data=json.dumps({
            'type': 'turn_state',
            'user': event['user'],
            'turn_state': event['turn_state']
        }))
    
    def message_limit_reached(self, event):
        """Handle message limit reached notification"""
        self.send(text_data=json.dumps({
            'type': 'message_limit_reached',
            'message': event['message'],
            'objective_index': event['objective_index'],
            'next_objective_index': event['next_objective_index']
        }))
    
    def session_completed(self, event):
        """Handle session completion notification"""
        self.send(text_data=json.dumps({
            'type': 'session_completed',
            'message': event['message']
        }))

    def websocket_close(self, event):
        """Handle forced WebSocket closure"""
        self.close(code=event.get('code', 1000))

    # WebSocket handlers for typing indicators (used for regular chat and transitions)
    def llm_typing_start(self, event):
        """Handle LLM typing start indicator"""
        message = event.get('message', 'AI Counselor is typing...')

        self.send(text_data=json.dumps({
            'type': 'llm_typing',
            'status': 'start',
            'message': message,
            'sender': 'llm'
        }))

    def llm_typing_stop(self, event):
        """Handle LLM typing stop indicator"""
        self.send(text_data=json.dumps({
            'type': 'llm_typing',
            'status': 'stop',
            'sender': 'llm'
        }))

    def session_started(self, event):
        """Handle session started event and trigger initial LLM response"""
        session_uuid = event['session_uuid']

        # Run the initial LLM response generation in a separate thread
        # to avoid blocking the WebSocket
        thread = threading.Thread(
            target=generate_initial_llm_response,
            args=(session_uuid,)
        )
        thread.daemon = True
        thread.start()

        # Note: Typing indicators are now handled by frontend based on message state

