# Dodeka Backend Specification

This document specifies the sync, registration, login, and permission flows
for the D.S.A.V. Dodeka backend. It is the authoritative reference for how
member accounts are created, maintained, and removed. This forms the core of
the backend application. It does not mention any _features_.

## Architecture overview

Two processes cooperate:

- **Python backend** -- public HTTP API (frontend-facing) and a private HTTP
  server on a separate loopback address (127.0.0.2).
- **Go auth server (tiauth-faroe)** -- handles authentication primitives
  (signup, signin, sessions, password reset). Calls back to the Python
  private server for user storage (`/invoke`) and email delivery (`/email`).

All persistent state lives in a single SQLite database accessed through
`freetser.Storage`. A `StorageQueue` serializes all database operations onto
a single thread. Blocking calls (HTTP, SMTP) must never run inside a
`store_queue.execute()` callback.

### Email identity

Email addresses are normalized by trimming surrounding whitespace and
lowercasing. This normalization is applied consistently at every ingress:

- public registration
- signin
- sync import
- email change
- private/admin commands

No provider-specific canonicalization is performed. The backend does not
collapse Gmail dot aliases, plus aliases, `gmail.com` / `googlemail.com`, or
other provider-specific variants. Email is treated as a verified contact and
login channel, not as the canonical identity of a person. Cross-email
continuity is handled through explicit email-change flows and Atletiekunie
`bondsnummer` matching.

## Registration

There are two ways a user gets an account in Dodeka. Both end with a
verified email and a password stored in Faroe, but they differ in who
initiates the process and when membership is granted.

All pre-account and pending-approval state is represented by one canonical
backend table:

- **`registrations`** -- keyed by normalized `email`. Each entry stores
  `email`, `firstname`, `lastname`, `accepted`, `account_created`,
  `registration_token`, `signup_token`, `email_send_count`, and
  `notify_on_completion`.
- **`registration_tokens`** -- keyed by `registration_token`, stores the
  normalized `email`. This is the stable public lookup index used by the
  frontend and by Faroe email callbacks.

The `registration_token` is the stable public handle for the entire
registration lifecycle. The Faroe `signup_token` is an internal short-lived
signup session identifier. A registration can exist without an active
`signup_token`.

Registration rows do not expire automatically. The Faroe signup session may
expire after approximately 20 minutes, but the Dodeka registration record
remains until the lifecycle is completed or explicitly removed.

### Sync registration

This is an important flow and necessary to migrate existing users and to 
onboard users who don't immediately make an account but do officially become 
members. A user is a full member in VoltaClub, but does not have an account on 
the website.

1. **Admin imports VoltaClub CSV** -- member data lands in the `sync` table.
2. **Admin runs "Accept All New"** -- for each new member, the backend:
   - Creates or updates a `registrations` entry with `accepted=True`,
     `account_created=False`, using the authoritative name from the CSV.
   - Ensures a `registration_token` exists and is indexed in
     `registration_tokens`.
   - Stores their sync data (`userdata`, birthday, bondsnummer index).
   - Sends a **sync_please_register** email with a signup link:
     `{frontend}/account/signup?token={registration_token}`.
3. **User clicks the link** -- the frontend reads `registration_token` from
   the URL and fetches the registration status. Because `accepted` is
   `True`, the frontend knows this user was already approved and can present
   the page accordingly. The frontend calls `renew_signup`, which starts a
   Faroe signup session. Faroe sends a **signup_verification** email with a
   verification code.
4. **User enters the verification code** -- or clicks the direct link in
   the verification email, which pre-fills the code.
5. **User sets a password.**
6. **Signup completes** -- Faroe finalizes the account by calling
   `create_user`. Because `accepted=True` in `registrations`, the `member`
   permission is granted immediately (1-year TTL). The registration row is
   deleted as soon as no deferred acceptance email remains to be sent. The
   user is now a full member.

**Emails sent (2+):**
1. `sync_please_register` -- "Create your account" with signup link (sent
   by the backend when the admin accepts).
2. `signup_verification` -- verification code (sent by Faroe when the user
   starts signup, expires in ~20 min; `renew_signup` sends a fresh one if
   needed).

### Self-registration

A user creates their account on their own via the website. They can log in
immediately, but membership requires admin approval.

1. **User submits the registration form** -- the backend normalizes the
   email, creates or reuses a `registrations` entry with `accepted=False`
   and `account_created=False`, ensures a stable `registration_token`, and
   immediately attempts to start a Faroe signup session.
2. **Faroe signup is started** -- Faroe sends a **signup_verification**
   email with a verification code. The resulting `signup_token` is stored in
   the registration row. If the Faroe signup cannot be created at that
   moment, the registration row still remains valid and the frontend can
   recover later through `renew_signup`.
3. **User enters the verification code** -- or clicks the direct link in
   the verification email. If the Faroe signup session expired before the
   user returned, the frontend calls `renew_signup` to get a fresh session
   and verification email.
4. **User sets a password.**
5. **Signup completes** -- Faroe finalizes the account by calling
   `create_user`. Because `accepted=False` in `registrations`, the account
   is created without the `member` permission. The registration row is kept
   with `account_created=True`. The user can log in but sees a
   `pending_approval` state and cannot access member-only areas.
6. **Admin accepts the user** (from the Registrations tab) -- the backend
   grants the `member` permission (1-year TTL), sends an
   **account_accepted_self** email if the account already exists, and
   deletes the registration row once the lifecycle is complete.

After step 6, the user is a full member.

**Emails sent (2+):**
1. `signup_verification` -- sent immediately at registration (may expire;
   `renew_signup` sends a fresh one).
2. `account_accepted_self` -- "Your membership is approved" (sent when the
   admin accepts, either immediately or on first session if acceptance
   happened before signup was completed).

### Public registration contract

The public registration flow is addressed by `registration_token`.

- **`request_registration(email, firstname, lastname)`**
  - normalizes the email
  - rejects if `users_by_email` already contains the email
  - creates or reuses `registrations[email]`
  - ensures `registration_tokens[registration_token] -> email`
  - attempts Faroe `create_signup(email)`
  - stores `signup_token` when Faroe signup succeeds
  - returns `registration_token` and the current `signup_token` when
    available
- **`registration_status(registration_token)`**
  - resolves `registration_token -> email`
  - returns the canonical registration state for that email
  - remains valid across Faroe signup expiry
- **`renew_signup(registration_token)`**
  - resolves `registration_token -> email`
  - starts a fresh Faroe signup for the current email
  - replaces the stored `signup_token`
  - sends a fresh `signup_verification` email

The frontend uses `registration_token` as the stable identity for a pending
registration. The `signup_token` is an ephemeral Faroe session token and is
not the primary public identifier.

### Faroe signup flow

Faroe handles the cryptographic parts of account creation:

1. **`create_signup(email)`** -- creates a signup session. Faroe
   immediately calls back to the Python `/email` endpoint with a
   `signup_verification` email containing a verification code. Returns a
   `signup_token`.
2. **`verify_signup_email_address_verification_code(signup_token, code)`**
   -- verifies the code the user entered.
3. **`set_signup_password(signup_token, password)`** -- sets the password.
4. **`complete_signup(signup_token)`** -- finalizes account creation. Faroe
   calls back to `/invoke`, which triggers `create_user` in `auth.py`.

**Timing constraint:** when `create_signup` is called, Faroe calls back to
the `/email` endpoint *during* the HTTP call (before `signup_token` is
returned to the caller). This means the signup link in the verification
email cannot use `signup_token`. Instead, the email link uses
`registration_token`, which already exists and is already bound to the
email in `registration_tokens`.

**Expiry:** Faroe signup sessions expire after approximately 20 minutes. If
the user doesn't complete signup in time, a new signup must be created via
`renew_signup` or `resend_signup_email`. The Dodeka registration row remains
valid throughout this process.

### Account creation (`create_user` in `auth.py`)

This function is called by Faroe (via `/invoke`) when `complete_signup`
succeeds. It:

1. Normalizes the email and rejects if `users_by_email` already contains it.
2. Requires a `registrations[email]` row with `account_created=False`.
3. Generates a `user_id` from an auto-incrementing counter and the user's
   name (for example `0_alice_smith`).
4. Stores user data in the `users` table and the email index in
   `users_by_email`.
5. If `accepted=True`: grants `member` permission (1-year TTL).
6. Sets `account_created=True` and clears the stored `signup_token`.
7. If `accepted=False`: keeps the registration row so pending approval
   remains representable.
8. If `accepted=True` and `notify_on_completion=False`: deletes the
   registration row and its `registration_tokens` index.
9. If `accepted=True` and `notify_on_completion=True`: keeps the
   registration row until `set_session` sends the deferred
   `account_accepted_self` email, then deletes it.

`create_user` never sends emails. It runs inside the Faroe `/invoke`
callback and must not block on SMTP. Any notification emails are handled
elsewhere (see [Deferred accepted email](#deferred-accepted-email-in-set_session)).

### Registration scenarios

The two primary flows above can interact in unexpected ways. The following
scenarios describe how the system handles each case.

#### Scenario 1: Self-registered, admin accepts BEFORE signup completes

A user registers on the website but doesn't finish their Faroe signup
before the admin reviews the Registrations tab.

1. **User submits registration form** -- `registrations[email]` is created
   with `accepted=False`, `account_created=False`, and an active
   `signup_token`.
2. **Admin accepts the user** -- `accept_user` sets `accepted=True` in the
   registration row and sets `notify_on_completion=True`. The
   **account_accepted_self** email is not sent yet.
3. **User completes signup** -- `create_user` sees `accepted=True`, grants
   `member`, sets `account_created=True`, and keeps the registration row
   because `notify_on_completion=True`.
4. **User's first session** -- after signup, the frontend calls
   `/cookies/set_session/`. The `set_session` handler detects
   `notify_on_completion=True`, sends the **account_accepted_self** email,
   clears the flag, and deletes the registration row and token index.

The end result is that the user is a full member immediately upon
completing signup, and the acceptance email is sent only once the account
is fully usable.

#### Scenario 2: Self-registered user appears in sync CSV (no account yet)

A user has self-registered, but before they complete signup, their email
also appears in a sync CSV import.

1. **User submitted registration form earlier** -- a registration row
   exists with `accepted=False`, `account_created=False`. Faroe signup may
   or may not still be active.
2. **Admin imports CSV and runs "Accept All"** -- `compute_groups` places
   this email in the `to_accept` group. `accept_new` updates the existing
   registration row to `accepted=True`, updates the stored name from the
   sync data, stores `userdata`, birthday, and the bondsnummer index, and
   sends a **sync_please_register** email.
3. **User completes signup** -- either via the original signup session or a
   renewed one. `create_user` sees `accepted=True`, grants `member`, and
   deletes the registration row when no deferred acceptance email remains.

The sync upgrades the self-registration by marking it as accepted and by
storing the authoritative member data from the CSV. The `registration_token`
does not change.

#### Scenario 3: Self-registered user appears in sync CSV (already has account)

A user has self-registered and completed signup. They have an account in
the `users` table, but their registration row still exists with
`accepted=False` and `account_created=True`, so they do not yet have the
`member` permission.

Their email then appears in a sync CSV import. `compute_groups` places this
email in the `to_accept` group. When `accept_new` processes the entry:

1. Grants `member` permission (1-year TTL).
2. Stores `userdata`, birthday, and the bondsnummer index from the sync
   data.
3. Updates the user profile with the authoritative name from the sync CSV.
4. Sends an **account_accepted_self** email.
5. Deletes the registration row and its token index.

From the user's perspective, acceptance through sync or through the manual
registrations tab leads to the same final state.

#### Scenario 4: Pending registration email changes before account creation

A person has a registration row for email `A`, but before account creation
their email changes to `B` in Atletiekunie while the same `bondsnummer`
still identifies the same member.

1. **Registration exists for `A`** -- the registration row stores
   `accepted` and `account_created=False`. Sync data and
   `users_by_bondsnummer` point at `A`.
2. **A later sync import contains the same `bondsnummer` with email `B`** --
   `compute_groups` detects an `email_change`. The member is treated as the
   same person, not as one departed user plus one new user.
3. **`update_existing` applies the email change** -- the backend migrates
   the pending registration from `A` to `B`, updates the sync-related
   tables, and keeps the same `registration_token`.
4. **Old signup state is invalidated** -- any stored `signup_token` for `A`
   is cleared. Future signup verification is sent only to `B`.
5. **User continues registration** -- the existing signup link still works
   because it resolves through the unchanged `registration_token`, but the
   next signup step creates a fresh Faroe signup for `B` and requires fresh
   verification of `B`.

At no point may both `A` and `B` remain active registration rows for the
same `bondsnummer`.

#### Departed members returning

When a member departs, their account is fully deleted (see
[Remove departed](#6-remove-departed-remove_departed)). This means:

- **Departed member self-registers:** there is no existing account, so
  `request_registration` works normally. The user goes through the standard
  self-registration flow.
- **Departed member returns in future sync CSV:** there is no existing
  account, so `compute_groups` classifies them in `to_accept`. They go
  through the standard sync registration flow (`accept_new` -> signup).

No special handling is needed. Departed members are indistinguishable from
first-time users.

## Sync lifecycle

The sync process imports member data from the Atletiekunie VoltaClub CSV
export and reconciles it with the user database. Every step is explicit and
admin-triggered.

### 1. Import CSV (`import_sync`)

The admin uploads a CSV file. The `sync` table is cleared and repopulated
with parsed entries. Each row becomes a `UserDataEntry` keyed by normalized
email.

The CSV uses the VoltaClub "alle velden" format with UTF-8 BOM.
Relevant columns: `Bondsnummer`, `Voornaam`, `Tussenvoegsel`, `Achternaam`,
`Geslacht`, `Geboortedatum`, `Email`, `Club lidmaatschap opzegdatum`.

Rows without an email are skipped. Emails are normalized to trimmed
lowercase. Bondsnummer is parsed as an integer.

### 2. Compute groups (`compute_groups`)

Read-only comparison of the `sync` table against the user database. The
groups map directly to admin actions: "Accept" processes `to_accept`,
"Update" processes `existing`, "Remove" processes `departed`.

Returns five groups:

- **to_accept** -- emails in sync that do not yet have full member status.
  This includes:
  - truly new people (not in `users_by_email`, not in `registrations`, not
    bondsnummer-matched)
  - self-registered users without an account (`registrations` exists with
    `accepted=False`, `account_created=False`)
  - self-registered users with an account but pending approval
    (`registrations` exists with `accepted=False`, `account_created=True`,
    and `users_by_email` contains the email)
- **pending_signup** -- emails whose registration row has `accepted=True`
  and `account_created=False`. These users have already been accepted but
  have not completed signup yet. Informational only.
- **existing** -- emails in sync that already correspond to full members.
  Includes bondsnummer-matched users whose email changed. Each entry pairs
  the sync data with the current `userdata` (which may be `null` if
  `update_existing` has not been run yet for this user).
- **departed** -- registered users (in `users_by_email`) with an active
  `member` permission who are not in the active sync set, or whose
  `opzegdatum` cancellation date lies in the past. Users whose email is
  being changed via bondsnummer matching are not considered departed.
- **email_changes** -- sync entries where the bondsnummer maps to an
  existing user or pending registration with a different email. Reports
  `old_email`, `new_email`, and `bondsnummer`.

System users are excluded from all groups.

Cancelled members (with an `opzegdatum` that is in the past) are treated as
departed even if present in the CSV. A future cancellation date is ignored
until that date has passed.

### 3. Accept (`accept_new`)

The admin reviews the `to_accept` group and triggers "Accept All". For each
entry, `accept_new` determines the appropriate action based on the user's
current state:

**Truly new** (not in `users_by_email`, not in `registrations`):

1. A `registrations` entry is created with `accepted=True`,
   `account_created=False`, and the authoritative name from the sync data.
2. A `registration_token` is created and indexed.
3. Sync data is stored (`userdata`, birthday, bondsnummer index).
4. A **sync_please_register** email is sent with a link to create the
   account.

**Self-registered, no account yet** (`registrations` exists with
`accepted=False`, `account_created=False`):

1. The registration row is updated to `accepted=True`.
2. The stored name is updated from the sync data.
3. Sync data is stored (`userdata`, birthday, bondsnummer index).
4. A **sync_please_register** email is sent.

When the user later completes their Faroe signup, `create_user` sees
`accepted=True` and grants `member` permission immediately. This is
[Scenario 2](#scenario-2-self-registered-user-appears-in-sync-csv-no-account-yet).

**Self-registered, has account** (`registrations` exists with
`accepted=False`, `account_created=True` and the email is in
`users_by_email`):

1. `member` permission is granted (1-year TTL).
2. Sync data is stored (`userdata`, birthday, bondsnummer index) and the
   user profile is updated with the authoritative name from the sync CSV.
3. An **account_accepted_self** email is sent.
4. The registration row and token index are deleted.

This is
[Scenario 3](#scenario-3-self-registered-user-appears-in-sync-csv-already-has-account).

### 4. Users sign up

After acceptance, truly new users receive an email with a link to create
their account. The signup process is detailed in [Sync
registration](#sync-registration).

### 5. Update existing (`update_existing`)

The admin triggers this after verifying the diff in the admin panel. This is
the step that actually writes data. For each entry in the `existing` group:

1. **Email changes are applied first.** For each `email_change` detected by
   bondsnummer matching, `update_user_email` migrates all references from
   `old_email` to `new_email` (see [Bondsnummer matching](#bondsnummer-matching)).
2. **Sync data is copied to userdata** (`sync_userdata`): the `userdata`
   table is updated with the sync entry.
3. **User profile is updated** (`users:{user_id}:profile`): firstname and
   lastname are updated from the sync data. The sync CSV is the
   authoritative source for names.
4. **Member permission is renewed** (1-year TTL).
5. **Bondsnummer index is updated.**
6. **Birthday table is updated** with `geboortedatum`, `voornaam`,
   `tussenvoegsel`, and `achternaam`.

Creating an account alone does not populate these tables. The `userdata`
and birthday tables are first populated by `accept_new` (for new entries)
and subsequently updated by `update_existing` (for existing members each
sync cycle).

### 6. Remove departed (`remove_departed`)

For each departed user, the account is fully deleted:

1. User account is deleted from the `users` table.
2. `users_by_email` index entry is deleted.
3. `userdata` entry is deleted.
4. Birthday entry is deleted.
5. Bondsnummer index entry is deleted.
6. Any `registrations` row and `registration_tokens` index for the email are
   deleted.
7. Existing sessions become invalid because session validation consults the
   current user state through the user server, and the user no longer exists.

After removal, the user has no presence in the system. If they return in a
future sync CSV or self-register, they go through the normal registration
flow as a new user.

## Login and sessions

### Signin flow

1. **Frontend calls `create_signin(email)`** on Faroe -- Faroe looks up the
   user via `/invoke` (`GetUserByEmailAddressEffect`).
2. **User enters password** -- Faroe verifies the password hash.
3. **Faroe creates a session** -- returns a `session_token`. Faroe sends a
   **signin_notification** email.
4. **Frontend calls `/cookies/set_session/`** -- the Python backend
   validates the session with Faroe, then sets an HttpOnly cookie.

### Deferred accepted email in `set_session`

When `set_session` validates a session and sets the cookie, it also checks
whether a deferred **account_accepted_self** email needs to be sent. This
handles [Scenario
1](#scenario-1-self-registered-admin-accepts-before-signup-completes) where
the admin accepted a self-registered user before they completed signup.

The mechanism:

1. `accept_user` sets `notify_on_completion=True` in `registrations` when
   it accepts a user who has no account yet.
2. After the user completes Faroe signup, the frontend calls
   `/cookies/set_session/`.
3. `set_session` looks up the user's email in `registrations`. If
   `notify_on_completion=True`, it sends the **account_accepted_self**
   email, clears the flag, and deletes the registration row and token index.

This keeps email sending out of `create_user` and ensures the user receives
the acceptance notification only after their account is fully ready.

### Session validation

Session tokens are validated with the Faroe auth server and cached in the
`session_cache` table for 8 hours to reduce auth server load.

### Session cookies

Two cookie slots exist:

- **Primary** (`session_token`) -- the user's logged-in session. Used by
  default for `session_info` and permission checks.
- **Secondary** (`session_token_secondary`) -- authorization-only fallback.
  Permission checks try primary first, then secondary. Useful for testing:
  log in as a regular user (primary) while using an admin session
  (secondary) for admin actions.

### Session info (`/auth/session_info/`)

Returns the current user's information:

- `user_id`, `email`, `firstname`, `lastname`
- `permissions` -- list of active permission names
- `pending_approval` -- whether the user still has a `registrations` row
  with `account_created=True` and `accepted=False`

The Dodeka public contract does not expose a `disabled` user field.

## Core database tables

| Table | Key | Value | Purpose |
|---|---|---|---|
| `users` | `{user_id}:{field}` | varies | User data: `:profile`, `:email`, `:password`, `:sessions_counter`, `:perm:{name}` |
| `users_by_email` | normalized email | user_id bytes | Email-to-user index |
| `users_by_bondsnummer` | `str(bondsnummer)` | normalized email bytes | Bondsnummer-to-email index |
| `registrations` | normalized email | JSON `{email, firstname, lastname, accepted, account_created, registration_token, signup_token, email_send_count, notify_on_completion}` | Canonical pre-account and pending-approval lifecycle state |
| `registration_tokens` | `registration_token` | normalized email bytes | Stable public registration lookup index |
| `metadata` | key | value | Global counters (for example `user_id_counter`) |
| `userdata` | normalized email | JSON `UserDataEntry` | Member data from sync |
| `sync` | normalized email | JSON `UserDataEntry` | Imported CSV data (replaced each import) |
| `system_users` | normalized email | `b"1"` | Users excluded from sync comparison |

## Permission system

Permissions are stored as separate keys in the `users` table:

    Key:   {user_id}:perm:{permission_name}
    Value: b""
    TTL:   1 year from grant (expires_at = timestamp + 365 days)

The storage layer filters expired entries automatically when `timestamp` is
passed to `store.get()`.

**Core permissions:**

- `member` -- grants access to member-only areas. Granted at signup (when
  accepted), granted at admin acceptance for pending-approval users, and
  renewed by `update_existing` each sync cycle.
- `admin` -- grants access to the admin panel and all admin API routes.

**Role permissions:** committee/group tags (`bestuur`, `comcom`, `batcie`,
etc.) with no special system behavior. Managed manually by admins and can
be used in future features.

**Expiry behavior:** permissions silently expire after 1 year. The sync
cycle (`update_existing`) renews the `member` permission for all active
members. If no sync is run within a year, the permission lapses. There is no
user-facing notification for expiry.

## System users

Certain accounts (root admin, board account) are marked as system users via
the `system_users` table. System users are excluded from sync comparison in
`compute_groups` -- they never appear as "departed" regardless of the CSV
contents.

The root admin (`root_admin@localhost`) is bootstrapped automatically at
server startup.

## Bondsnummer matching

The `bondsnummer` (athletics union member number) is a stable identifier.
When a member changes their email in the athletics union system, the CSV
will have the same bondsnummer but a new email. Without bondsnummer
matching, this would incorrectly show as one departed user plus one new
member.

### How it works

1. When `sync_userdata` or `accept_new` runs, the bondsnummer index
   (`users_by_bondsnummer`) is populated: `str(bondsnummer)` -> normalized
   email.
2. `compute_groups` calls `detect_email_changes`, which checks each sync
   entry's bondsnummer against the index. If a bondsnummer maps to a
   different email, it is reported as an `email_change`.
3. Bondsnummer-matched entries are treated as "existing", and the old email
   is not marked "departed".
4. `update_existing` applies email changes before syncing userdata. The
   `update_user_email` function migrates all references:
   - `users_by_email`: delete old, add new
   - `users:{user_id}:email`: update to new email
   - `userdata`: delete old key, insert new key
   - `users_by_bondsnummer`: update to new email
   - `registrations`: migrate the row if it exists
   - `registration_tokens`: keep the same `registration_token` but point it
     at the new email
   - `birthdays`: migrate the key if it exists
5. If the migrated registration had `account_created=False`, any stored
   `signup_token` is cleared and future verification is sent only to the new
   email address.

The bondsnummer index is deleted when a user departs, along with the rest
of their account data. If a departed member returns in a future CSV, they
are treated as a new member.

## Email notifications

### Email types

There are two categories:

**Backend-initiated** (sent by Python code directly):
- `sync_please_register` -- sync-imported member, invites them to create an
  account
- `account_accepted_self` -- self-registered member, tells them membership
  is approved

**Faroe-initiated** (Faroe calls back to `/email` on the private server):
- `signup_verification`
- `email_update_verification`
- `password_reset`
- `signin_notification`
- `password_updated`
- `email_updated`

### Email: `sync_please_register`

Sent when the admin runs "Accept All New" for sync-imported members and for
self-registrations that become accepted through sync.

- **Subject:** "Maak je Dodeka account aan"
- **Content:** tells the user their registration with D.S.A.V. Dodeka is
  complete and invites them to create a website account. Includes a link to
  `{frontend}/account/signup?token={registration_token}`.
- **Purpose:** provides the stable entry point for the rest of the signup
  lifecycle.
- **Sent by:** Python backend.

### Email: `account_accepted_self`

Sent when a self-registered user's membership is approved. This can happen
in three ways:

1. The admin manually accepts from the Registrations tab after the user has
   completed signup.
2. `accept_new` detects a self-registered user who already has an account
   in the sync CSV.
3. The user completes signup after being pre-accepted by the admin; in that
   case `set_session` sends the email on the first session.

- **Subject:** "Je lidmaatschap bij Dodeka is goedgekeurd"
- **Content:** tells the user their membership has been approved. Links to
  the homepage.
- **Purpose:** confirms that the account now has full member access.
- **Sent by:** Python backend.

### Email: `signup_verification`

Sent by Faroe when `create_signup` or `renew_signup` is called.

- **Subject:** "Activeer je Dodeka account"
- **Content:** "Je verificatiecode is: {code}" with a link to
  `{frontend}/account/signup?token={registration_token}&code={code}`.
- **Purpose:** email address verification. The code must be entered on the
  signup page to prove email ownership.
- **Expires:** ~20 minutes (Faroe signup session lifetime).
- **Link construction:** the Python `/email` handler resolves
  `registration_token` from the current email and constructs the link. The
  `registration_token` is used instead of `signup_token` because of the
  timing constraint described in [Faroe signup flow](#faroe-signup-flow).
- **Token storage:** the verification code is stored in the `tokens` table
  (`signup_verification:{email}`) for test automation.

### Email: `email_update_verification`

Sent by Faroe when a user requests an email address change.

- **Subject:** "Bevestig je nieuwe e-mailadres"
- **Content:** "Je verificatiecode voor het wijzigen van je e-mailadres is:
  {code}"
- **Purpose:** verify ownership of the new email address.

### Email: `password_reset`

Sent by Faroe when a password reset is requested.

- **Subject:** "Wachtwoord resetten"
- **Content:** "Je tijdelijke wachtwoord is: {code}"
- **Purpose:** provide a temporary password for the user to log in with.

### Email: `signin_notification`

Sent by Faroe after a successful signin.

- **Subject:** "Nieuwe aanmelding gedetecteerd"
- **Content:** "Er is ingelogd op je account op {timestamp} (UTC)."
- **Purpose:** security notification.

### Email: `password_updated`

Sent by Faroe after a password change.

- **Subject:** "Je wachtwoord is gewijzigd"
- **Content:** "Je wachtwoord is gewijzigd op {timestamp} (UTC)."
- **Purpose:** security notification.

### Email: `email_updated`

Sent by Faroe after an email address change is completed.

- **Subject:** "Je e-mailadres is gewijzigd"
- **Content:** "Je e-mailadres is gewijzigd naar {new_email} op {timestamp}
  (UTC)."
- **Purpose:** security notification sent to the old email address.

## Admin operations

### Board account

The board account (`bestuur@dsavdodeka.nl`) is a special admin account:

- **`board_setup`:** one-time creation. Prepares the account as an accepted
  user, marks it as a system user, and initiates Faroe signup.
- **`board_renew`:** yearly renewal when the board rotates. Triggers
  password reset and renews admin permission.

### Permission management

Admins can manage permissions via:

- `POST /admin/add_permission/` -- add a single permission (except admin)
- `POST /admin/remove_permission/` -- remove a single permission
- `POST /admin/set_permissions/` -- declaratively set permissions for
  multiple users (add missing, remove extra, never touches admin permission)

The `admin` permission cannot be added through the public API. It can only
be granted via the private admin path.
