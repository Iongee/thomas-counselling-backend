from django.urls import path
from . import views
from .views import (CsrfCookie, Login, Logout, CurrentUser,
                    Register, StartCounsellingSession, ReflectionCreate,
                    SessionMembership, SessionMessages, UserSessions,
                    SendRelationshipInvitation, RespondToRelationshipInvitation,
                    UserNetwork, UserRelationships, RemoveRelationship, DeleteUserAccount,
                    UserRelationshipsForSession, RelationshipDetail,
                    RespondToSessionInvitation, UserSessionInvitations,
                    SessionTurnState, DeleteSession, CancelRelationshipInvitation,
                    GenerateObjectives, RefineObjectives, CreateSessionWithObjectives,
                    SessionDetail, ObjectiveMessages, CompleteObjective,
                        VoteToMoveNext, MoveToNextObjective, VoteToEndSession, SubmitSummaryResponse,
    GetSessionSummary, SSEView, TestSSENotification, sse_stream)

urlpatterns = [
    path('api/set-csrf-token', CsrfCookie.as_view(), name='set_csrf_token'),
    path('api/login', Login.as_view(), name='login'),
    path('api/logout', Logout.as_view(), name='logout'),
    path('api/user', CurrentUser.as_view(), name='user'),
    path('api/register', Register.as_view(), name='register'),
    path('api/delete-account', DeleteUserAccount.as_view(), name='delete_user_account'),
    path('api/start-counselling-session/',StartCounsellingSession.as_view(), name='start_counselling_session'),
    path('api/submit-reflection/',ReflectionCreate.as_view(), name='submit_reflection'),

    path('api/check-session-user/',SessionMembership.as_view(), name='check_session_user'),
    path('api/get-messages/<str:session_uuid>/',SessionMessages.as_view(), name='get_messages'),
    path('api/user-sessions/',UserSessions.as_view(), name='get_user_sessions'),
    path('api/session-turn-state/<str:session_uuid>/', SessionTurnState.as_view(), name='session_turn_state'),
    path('api/delete-session/<str:session_uuid>/', DeleteSession.as_view(), name='delete_session'),
    
    # New objective-based endpoints
    path('api/session/<str:session_uuid>/', SessionDetail.as_view(), name='session_detail'),
    path('api/objective-messages/<str:session_uuid>/<int:objective_index>/', ObjectiveMessages.as_view(), name='objective_messages'),
    path('api/complete-objective/<str:session_uuid>/<int:objective_index>/', CompleteObjective.as_view(), name='complete_objective'),
    
    # Voting endpoints
    path('api/vote-move-next/<str:session_uuid>/<int:objective_index>/', VoteToMoveNext.as_view(), name='vote_move_next'),
    path('api/move-to-next-objective/<str:session_uuid>/', MoveToNextObjective.as_view(), name='move_to_next_objective'),
    
    # Session completion endpoints
    path('api/vote-end-session/<str:session_uuid>/', VoteToEndSession.as_view(), name='vote_end_session'),
    path('api/submit-summary-response/<str:session_uuid>/', SubmitSummaryResponse.as_view(), name='submit_summary_response'),
    path('api/get-session-summary/<str:session_uuid>/', GetSessionSummary.as_view(), name='get_session_summary'),
    
    # Relationship management endpoints
    path('api/send-relationship-invitation/', SendRelationshipInvitation.as_view(), name='send_relationship_invitation'),
    path('api/respond-to-relationship-invitation/', RespondToRelationshipInvitation.as_view(), name='respond_to_relationship_invitation'),
    path('api/user-network/', UserNetwork.as_view(), name='user_network'),
    path('api/user-relationships/', UserRelationships.as_view(), name='user_relationships'),
    path('api/remove-relationship/<int:relationship_id>/', RemoveRelationship.as_view(), name='remove_relationship'),
    path('api/user-relationships-for-session/', UserRelationshipsForSession.as_view(), name='user_relationships_for_session'),
    path('api/relationship-detail/<int:relationship_id>/', RelationshipDetail.as_view(), name='relationship_detail'),
    path('api/cancel-relationship-invitation/<str:invitation_uuid>/', CancelRelationshipInvitation.as_view(), name='cancel_relationship_invitation'),
    
    # Session invitation endpoints
    path('api/respond-session-invitation/', RespondToSessionInvitation.as_view(), name='respond_session_invitation'),
    path('api/user-session-invitations/', UserSessionInvitations.as_view(), name='user_session_invitations'),
    
    # Objective generation endpoints
    path('api/generate-objectives/', GenerateObjectives.as_view(), name='generate_objectives'),
    path('api/refine-objectives/', RefineObjectives.as_view(), name='refine_objectives'),
    path('api/create-session-with-objectives/', CreateSessionWithObjectives.as_view(), name='create_session_with_objectives'),
    
    # SSE endpoints
    path('api/sse/', SSEView.as_view(), name='sse_stream_class'),
    path('api/sse-simple/', sse_stream, name='sse_stream'),
    
    # Test endpoint
    path('api/test-sse/', TestSSENotification.as_view(), name='test_sse'),
]
