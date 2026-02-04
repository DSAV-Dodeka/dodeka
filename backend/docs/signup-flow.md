# Signup Flow Documentation

This document describes the complete user registration and signup flow, including the interplay between the Frontend, Python Backend, and Go/Faroe authentication server.

## Overview

The signup process has two main phases:
1. **Registration**: User submits their details and waits for admin approval
2. **Activation**: After approval, user receives an email and activates their account

## Components

- **Frontend** (`dodekafrontend`): React application handling UI
- **Backend** (`dodeka/backend`): Python server handling business logic and email
- **Faroe** (`tiauth-faroe`): Go server wrapping the Faroe authentication library

## Phase 1: Registration

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Frontend   │     │   Backend   │     │    Faroe    │
│  (React)    │     │  (Python)   │     │    (Go)     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │ POST /auth/request_registration       │
       │ {email, firstname, lastname}          │
       ├──────────────────>│                   │
       │                   │                   │
       │                   │ Store in newusers │
       │                   │ table             │
       │                   │                   │
       │                   │ Create            │
       │                   │ registration_state│
       │                   │ with unique token │
       │                   │                   │
       │ {registration_token}                  │
       │<──────────────────│                   │
       │                   │                   │
       │ Redirect to       │                   │
       │ /account/signup?token=...             │
       │                   │                   │
```

### Key Points:
- `registration_token` is generated and stored immediately
- User is redirected to the signup page with the token in the URL
- Page shows "waiting for approval" message and polls for status

## Phase 2: Admin Approval & Email

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Admin     │     │   Backend   │     │    Faroe    │
│  Frontend   │     │  (Python)   │     │    (Go)     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │ POST /admin/accept_user/              │
       │ {email}           │                   │
       ├──────────────────>│                   │
       │                   │                   │
       │                   │ create_signup(email)
       │                   ├──────────────────>│
       │                   │                   │
       │                   │     ┌─────────────┴─────────────┐
       │                   │     │ Faroe internally:         │
       │                   │     │ 1. Generate signup_token  │
       │                   │     │ 2. Generate verify code   │
       │                   │     │ 3. Store signup record    │
       │                   │     │ 4. Call email sender      │
       │                   │     └─────────────┬─────────────┘
       │                   │                   │
       │                   │ POST /email       │
       │                   │ {type, email, code}
       │                   │<──────────────────│
       │                   │                   │
       │                   │ Lookup registration_token by email
       │                   │ (exists from Phase 1)
       │                   │                   │
       │                   │ Build link with token + code
       │                   │ Save/send email   │
       │                   │                   │
       │                   │ 200 OK            │
       │                   ├──────────────────>│
       │                   │                   │
       │                   │ {signup_token}    │
       │                   │<──────────────────│
       │                   │                   │
       │                   │ Store signup_token│
       │                   │ in registration_state
       │                   │                   │
       │ {success, signup_token}               │
       │<──────────────────│                   │
       │                   │                   │
```

### The Timing Problem (Solved)

There's a critical timing issue in this flow:

1. When Python calls `create_signup()`, it **blocks** waiting for Go to return
2. Inside `create_signup()`, Go/Faroe sends the verification email by calling Python's `/email` endpoint
3. At this point, `signup_token` hasn't been stored yet (that happens after `create_signup()` returns)

**Solution**: Use `registration_token` (which exists from Phase 1) instead of `signup_token` for the email link. The `registration_token` is looked up by email when the email request arrives.

### Email Contents

The signup verification email contains:
- **Verification code**: 8-character alphanumeric code
- **Link**: `{frontend_origin}/account/signup?token={registration_token}&code={code}`

The link includes both the token and code, so clicking it pre-fills the verification code.

## Phase 3: Account Activation

### Option A: Click Link from Email

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   User      │     │   Backend   │     │    Faroe    │
│  Frontend   │     │  (Python)   │     │    (Go)     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │ Navigate to       │                   │
       │ /account/signup?token=...&code=...    │
       │                   │                   │
       │ POST /auth/registration_status        │
       │ {registration_token}                  │
       ├──────────────────>│                   │
       │                   │                   │
       │ {email, accepted: true, signup_token} │
       │<──────────────────│                   │
       │                   │                   │
       │ Form pre-filled with code from URL    │
       │ User enters password                  │
       │                   │                   │
       │ (via SignupFlow)  │                   │
       │ Verify code, set password, complete   │
       │ ───────────────────────────────────────────>
       │                   │                   │
       │ {session_token}   │                   │
       │<───────────────────────────────────────────
       │                   │                   │
       │ User is now logged in                 │
       │                   │                   │
```

### Option B: Enter Email + Code Manually

For users who don't have the link (e.g., checking email on different device):

```
┌─────────────┐     ┌─────────────┐
│   User      │     │   Backend   │
│  Frontend   │     │  (Python)   │
└──────┬──────┘     └──────┬──────┘
       │                   │
       │ Navigate to       │
       │ /account/signup   │
       │ (no token in URL) │
       │                   │
       │ Shows email+code form
       │                   │
       │ POST /auth/lookup_registration
       │ {email, code}     │
       ├──────────────────>│
       │                   │
       │                   │ Verify code matches
       │                   │ stored token for email
       │                   │
       │                   │ If match, return
       │                   │ registration_token
       │                   │
       │ {found: true, token: ...}
       │<──────────────────│
       │                   │
       │ Redirect to       │
       │ /account/signup?token=...&code=...
       │                   │
       │ (continues as Option A)
       │                   │
```

### Security Note

The `/auth/lookup_registration` endpoint requires **both** email AND the correct verification code. Email alone will not reveal:
- Whether a registration exists
- The registration token
- Any other registration state

This prevents enumeration attacks.

## Database Tables

### newusers
Stores pending registrations:
- `email`: User's email address
- `firstname`, `lastname`: User's name
- `accepted`: Whether admin has approved

### registration_state
Tracks registration progress:
- Key: `registration_token` (generated at registration)
- `email`: User's email
- `accepted`: Whether approved
- `signup_token`: Set after admin approval (from Faroe)

### tokens
Stores verification codes for testing/automation:
- `{email_type}:{email}` → `{code, timestamp}`

## Email Templates

Located in `src/apiserver/resources/templates/`:
- `base.html`: Cerberus-based responsive email template
- `signup_verification.{txt,html}`: Signup verification email
- Other email types for password reset, notifications, etc.

## Configuration

### Environment Variables
- `BACKEND_SMTP_HOST`, `BACKEND_SMTP_PORT`: SMTP server
- `BACKEND_SMTP_SEND`: Set to `true` to actually send emails
- `BACKEND_FRONTEND_ORIGIN`: Base URL for email links

When `BACKEND_SMTP_SEND` is not `true`, emails are saved to the `emails/` directory instead of being sent.

## Sequence Summary

1. User registers → gets `registration_token` → waits for approval
2. Admin approves → Python calls Faroe's `create_signup`
3. Faroe generates `signup_token` and calls back to send email
4. Email includes link with `registration_token` + `code`
5. Faroe returns `signup_token` to Python
6. Python stores `signup_token` in `registration_state`
7. User clicks link (or enters email+code manually)
8. Frontend fetches status, shows form, completes signup via Faroe
9. User is logged in with session
