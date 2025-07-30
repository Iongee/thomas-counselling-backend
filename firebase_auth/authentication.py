import os
import uuid

import firebase_admin
from django.conf import settings
from django.contrib.auth import get_user_model, authenticate
from django.utils import timezone
from firebase_admin import auth
from firebase_admin import credentials
from rest_framework import authentication
from rest_framework import exceptions

from .exceptions import FirebaseError, InvalidAuthToken, NoAuthToken, EmailNotVerified
from dotenv import load_dotenv 

load_dotenv()

firebase_credentials_path = os.getenv("FIREBASE_CREDENTIALS_PATH")
cred = credentials.Certificate(firebase_credentials_path)
default_app = firebase_admin.initialize_app(cred)

User = get_user_model() 

class FirebaseAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        if not auth_header:
            raise NoAuthToken("No auth token provided")

        id_token = auth_header.split(" ").pop()

        # Validate token format
        if not id_token or len(id_token) < 20:
            raise InvalidAuthToken("Invalid token format")

        decoded_token = None
        try:
            # Use increased clock skew tolerance for network delays
            decoded_token = auth.verify_id_token(id_token, clock_skew_seconds=60)
        except Exception as e:
            # Provide more specific error messages
            error_str = str(e).lower()
            if 'expired' in error_str:
                raise InvalidAuthToken("Token expired - please refresh your session")
            elif 'invalid' in error_str or 'malformed' in error_str:
                raise InvalidAuthToken("Invalid token format")
            else:
                raise InvalidAuthToken(f"Token verification failed: {str(e)}")

        if not id_token or not decoded_token:
            return None

        is_email_verified = decoded_token.get("email_verified", False)

        if not is_email_verified:
            raise EmailNotVerified()
        try:
            uid = decoded_token.get("uid")
        except Exception:
            raise FirebaseError("The user provided with the auth token is not a valid Firebase user, it has no Firebase UID")
        
        try:
            firebase_user = auth.get_user(uid)
            email = firebase_user.email
            display_name = firebase_user.display_name 
            if not display_name:
                random_suffix = str(uuid.uuid4())[:8]
                new_display_name = f"user_{random_suffix}"
                auth.update_user(uid, display_name=new_display_name)
                display_name = new_display_name
        except:
            raise FirebaseError("Could not get user record from Firebase.")

        user, created = User.objects.get_or_create(
            username=uid, 
            defaults={
                'email': email,
                'display_name': display_name
            }
        )
        
        if not created:
            user_updated = False
            if user.email != email:
                user.email = email
                user_updated = True

            if user.display_name != display_name:
                user.display_name = display_name
                user_updated = True
            
            if user_updated:
                user.save()

        return (user, None)
