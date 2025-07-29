from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/socket-server/<str:session_uuid>/', consumers.ChatConsumer.as_asgi()),  # Session-wide connections
    path('ws/socket-server/<str:session_uuid>/<int:objective_index>/', consumers.ChatConsumer.as_asgi()),  # Backward compatibility
]