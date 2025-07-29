

- **Backend**: Django 5.2.1, Django Channels (WebSockets), Django REST Framework
- **Frontend**: Vue.js 3, Pinia (state management), Tailwind CSS
- **Database**: SQLite
- **Authentication**: Firebase Auth
- **AI Integration**: OpenRouter API with DeepSeek models
- **Real-time**: WebSocket connections for live chat

## Recent Updates (July 18th, 2025)

### Message Limit & Objective Management System
- ✅ **100 Message Limit**: Auto-advance to next objective after 100 messages
- ✅ **Enhanced Voting System**: 
  - Minimum 20 messages required before voting option appears
  - Shows who initiated the vote proposal
  - Allow participants to reject votes and continue current objective
  - Visual feedback for vote status and participant responses
- ✅ **Read-Only Previous Objectives**: View chat history of completed objectives
- ✅ **Real-time Message Counting**: Live display of message count (X/100)
- ✅ **Auto-Advance Logic**:  transition between objectives when limits reached

### UI/UX Improvements
- ✅ **Enhanced Chat Interface**: 
  - Objective-based sidebar with progress tracking
  - Real-time connection status indicators
  - Improved message display with sender identification
- ✅ **Voting Interface**:
  - "Propose Moving to Next" button after 20 messages
  - Clear vote status with initiator identification
  - Agree/Reject buttons for democratic progression
- ✅ **Loading States**:  loading indicators during authentication and data fetching
- ✅ **Security Enhancements**: Route protection and navigation guards

### Backend Enhancements
- ✅ **New API Endpoints**:
  - `POST /api/vote-move-next/{session_uuid}/{objective_index}/` - Voting system
  - `POST /api/move-to-next-objective/{session_uuid}/` - Manual objective advancement
  - Enhanced objective message retrieval with voting data
- ✅ **Database Schema Updates**:
  - Added `move_to_next_votes` JSONField for vote tracking
  - Added `vote_initiated_by` and `vote_active` fields
  - Enhanced ObjectiveRoom model with voting capabilities
- ✅ **WebSocket Improvements**: 
  - Message limit detection and auto-advancement
  - Vote state synchronization across participants
  - Session completion handling


## Key Models

- **Session**: Main counseling session with objectives and participant management
- **ObjectiveRoom**: Individual objective-focused chat rooms with voting capabilities
- **Round**: Message grouping within objectives
- **Message**: Individual chat messages with sender tracking
- **LLMResponse**: AI-generated responses and guidance
- **SessionParticipant**: User participation in sessions
- **Reflection**: Pre-session participant reflections

## API Endpoints

- Authentication: `/api/login`, `/api/register`, `/api/logout`
- Sessions: `/api/session/{uuid}/`, `/api/user-sessions/`
- Objectives: `/api/objective-messages/{uuid}/{index}/`
- Voting: `/api/vote-move-next/{uuid}/{index}/`
- Relationships: `/api/user-relationships/`, `/api/send-relationship-invitation/`




