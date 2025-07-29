import json
import os
import requests
from django.conf import settings


class OpenRouterService:
    
    def __init__(self):
        self.api_key = os.getenv('OPENROUTER_API_KEY')
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY environment variable is required")
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        self.default_model = "deepseek/deepseek-chat-v3-0324:free"
        self.timeout = 5
    
    def _make_request(self, messages, max_tokens=1000, temperature=0.7):
        headers = {
            "Content-type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        
        payload = {
            "model": self.default_model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        
        response = requests.post(
            url=self.base_url,
            headers=headers,
            data=json.dumps(payload),
            timeout=self.timeout
        )
        
        response.raise_for_status()
        response_data = response.json()
        return response_data['choices'][0]['message']['content']
    
    def generate_session_objectives(self, session_context, categories, partner_info=None):
  
        categories_text = ", ".join(categories) if categories else "General relationship counseling"
        
        context_part = f"\nSession context: {session_context}" if session_context else ""
        partner_part = f"\nPartner information: {partner_info}" if partner_info else ""
        
        system_prompt = f"""You are an expert relationship counselor creating session objectives.

Session categories: {categories_text}{context_part}{partner_part}

Please generate 1-5 clear objectives for this counseling session.""".strip()
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Please provide the session objectives."}
        ]
        
        return self._make_request(messages, max_tokens=500)
    
    def refine_session_objectives(self, current_objectives, user_feedback):
        """
        Refine existing objectives based on user feedback.
        
        Args:
            current_objectives: List of current objectives
            user_feedback: User's feedback on the objectives
            
        Returns:
            str: Refined objectives as a string
        """
        objectives_text = "\n".join([f"- {obj}" for obj in current_objectives])
        
        system_prompt = f"""You are an expert relationship counselor refining session objectives based on user feedback.

Current objectives:
{objectives_text}

User feedback: {user_feedback}

Please provide the refined list of objectives based on this feedback.""".strip()
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Please provide the refined objectives."}
        ]
        
        return self._make_request(messages, max_tokens=500)
    
    def generate_session_greeting(self, session, participants_info):
        """
        Generate the initial session greeting message.
        
        Args:
            session: Session object with objectives and context
            participants_info: Information about session participants
            
        Returns:
            str: Generated greeting message
        """
        session_objectives = session.objectives if session.objectives else []
        session_categories = session.categories if session.categories else []
        session_context = session.context.strip() if session.context else ""
        
        # Build session info parts
        session_info_parts = []
        
        if session_objectives:
            objectives_text = "\n".join([f"• {obj}" for obj in session_objectives])
            session_info_parts.append(f"SESSION OBJECTIVES:\n{objectives_text}")
        
        if session_categories:
            categories_text = ", ".join(session_categories)
            session_info_parts.append(f"SESSION FOCUS AREAS: {categories_text}")
        
        if session_context:
            session_info_parts.append(f"SESSION CONTEXT:\n{session_context}")
        
        # Add participant reflections
        participants_text = "\n".join([f"• {info}" for info in participants_info])
        session_info_parts.append(f"PARTICIPANT REFLECTIONS:\n{participants_text}")
        
        session_context_block = "\n\n".join(session_info_parts)
        
        system_prompt = f"""You are a warm, conversational, emotionally intelligent AI counselor.
Your role is to guide two partners through sensitive relationship conversations toward their agreed objectives.

CORE SESSION GUIDANCE:
{session_context_block}

COMMUNICATION STYLE:
• Keep responses conversational and direct, as if speaking naturally
• Use "you both" or "you two" when addressing the couple
• Ask one clear, focused question at a time
• Acknowledge feelings and validate experiences
• Guide toward the session objectives naturally
• Keep responses to 2-3 sentences maximum

REMEMBER: Respond as if you're speaking directly to the participants. No formatting, no notes, just natural conversation."""
        
        user_context = """Both participants are now ready to begin their counseling session. Please provide your opening greeting and first question that helps them start working toward their session objectives while acknowledging their individual reflections."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_context}
        ]
        
        return self._make_request(messages, max_tokens=300)


    def generate_conversation_response(self, session, conversation_summary):
        """
        Generate a response during an ongoing conversation.

        Args:
            session: Session object with objectives and context
            conversation_summary: Summary of the conversation so far

        Returns:
            str: Generated response message
        """
        session_objectives = session.objectives if session.objectives else []
        session_categories = session.categories if session.categories else []
        session_context = session.context.strip() if session.context else ""

        # Build session info parts
        session_info_parts = []

        if session_objectives:
            objectives_text = "\n".join([f"• {obj}" for obj in session_objectives])
            session_info_parts.append(f"SESSION OBJECTIVES:\n{objectives_text}")

        if session_categories:
            categories_text = ", ".join(session_categories)
            session_info_parts.append(f"SESSION FOCUS AREAS: {categories_text}")

        if session_context:
            session_info_parts.append(f"SESSION CONTEXT:\n{session_context}")

        session_context_block = "\n\n".join(session_info_parts)

        system_prompt = f"""You are a warm, conversational, emotionally intelligent AI counselor.
Your role is to guide two partners through sensitive relationship conversations toward their agreed objectives.

CORE SESSION GUIDANCE:
{session_context_block}

COMMUNICATION STYLE:
• Keep responses conversational and direct, as if speaking naturally
• Use "you both" or "you two" when addressing the couple
• Ask one clear, focused question at a time
• Acknowledge feelings and validate experiences
• Guide toward the session objectives naturally
• Keep responses to 2-3 sentences maximum

REMEMBER: Respond as if you're speaking directly to the participants. No formatting, no notes, just natural conversation."""

        user_prompt = f"Here is the conversation so far:\n\n{conversation_summary}\n\nPlease provide your next counseling response that helps them work toward their session objectives."

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        return self._make_request(messages, max_tokens=300)

    def generate_objective_introduction(self, session, objective_room):
        """
        Generate an introduction message for a specific objective.

        Args:
            session: Session object with objectives and context
            objective_room: ObjectiveRoom object with objective details

        Returns:
            str: Generated objective introduction message
        """
        session_objectives = session.objectives if session.objectives else []
        session_categories = session.categories if session.categories else []
        session_context = session.context.strip() if session.context else ""

        objective_number = objective_room.objective_index + 1
        objective_text = objective_room.objective_text

        # Build session info parts
        session_info_parts = []

        if session_objectives:
            objectives_text = "\n".join([f"• {obj}" for obj in session_objectives])
            session_info_parts.append(f"SESSION OBJECTIVES:\n{objectives_text}")

        if session_categories:
            categories_text = ", ".join(session_categories)
            session_info_parts.append(f"SESSION FOCUS AREAS: {categories_text}")

        if session_context:
            session_info_parts.append(f"SESSION CONTEXT:\n{session_context}")

        session_context_block = "\n\n".join(session_info_parts)

        system_prompt = f"""You are a warm, conversational, emotionally intelligent AI counselor.
Your role is to guide two partners through sensitive relationship conversations toward their agreed objectives.

CORE SESSION GUIDANCE:
{session_context_block}

CURRENT OBJECTIVE: {objective_text}

COMMUNICATION STYLE:
• Keep responses conversational and direct, as if speaking naturally
• Use "you both" or "you two" when addressing the couple
• Ask one clear, focused question at a time
• Acknowledge feelings and validate experiences
• Guide toward the current objective naturally
• Keep responses to 2-3 sentences maximum

REMEMBER: Respond as if you're speaking directly to the participants. No formatting, no notes, just natural conversation."""

        user_context = f"""The participants have just entered the chat room for objective {objective_number}. Please provide your opening message that introduces this objective and helps them start working on it."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_context}
        ]

        return self._make_request(messages, max_tokens=300)


    def generate_session_summary(self, session, summary_responses):
        """
        Generate a comprehensive session summary.

        Args:
            session: Session object with objectives and context
            summary_responses: List of participant summary responses

        Returns:
            str: Generated session summary
        """
        session_objectives = session.objectives if session.objectives else []
        session_categories = session.categories if session.categories else []
        session_context = session.context.strip() if session.context else ""

        # Build session info
        session_info_parts = []

        if session_objectives:
            objectives_text = "\n".join([f"• {obj}" for obj in session_objectives])
            session_info_parts.append(f"SESSION OBJECTIVES:\n{objectives_text}")

        # if session_categories:
        #     categories_text = ", ".join(session_categories)
        #     session_info_parts.append(f"SESSION FOCUS AREAS: {categories_text}")

        # if session_context:
        #     session_info_parts.append(f"SESSION CONTEXT:\n{session_context}")

        # Add participant responses
        if summary_responses:
            responses_text = "\n".join([
                f"• {response.user.display_name}: {response.how_you_feel_now}"
                for response in summary_responses
            ])
            session_info_parts.append(f"PARTICIPANT REFLECTIONS ON SESSION:\n{responses_text}")

        session_context_block = "\n\n".join(session_info_parts)

        system_prompt = f"""You are an expert relationship counselor creating a comprehensive session summary.

{session_context_block}

Create a thoughtful summary that:
- Acknowledges the original objectives and how the session addressed them
- Incorporates insights from both participants' reflections
- Synthesizes the journey from initial objectives to current feelings
- Provides meaningful next steps based on both the objectives and personal insights shared"""

        user_prompt = "Please create a comprehensive session summary based on the information provided."

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        return self._make_request(messages, max_tokens=800, temperature=0.8)


# Create a singleton instance
openrouter_service = OpenRouterService()
