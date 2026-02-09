# Dodeka Backend Specification

This document specifies the sync, registration, login, and permission flows
for the D.S.A.V. Dodeka backend. It is the authoritative reference for how
member accounts are created, maintained, and removed.

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

## Registration

There are two ways a user gets an account in Dodeka. Both end with a
verified email and a password stored in Faroe, but they differ in who
initiates the process and when membership is granted.

Both flows use two backend tables to track users before they have a full
account:

- **`newusers`** -- a holding table for users who don't yet have an
  account. Each entry stores `email` (also the key), `firstname`,
  `lastname`, and an `accepted` boolean. A user cannot complete Faroe
  signup unless they have an entry in `newusers` (enforced by
  `create_user`). The `accepted` flag determines whether the `member`
  permission is granted at account creation.
- **`registration_state`** -- tracks signup progress. Keyed by a
  `registration_token` (a random URL-safe string generated at
  registration). Stores `email`, `accepted`, `signup_token` (Faroe's
  short-lived signup session identifier, ~20 min),
  `email_send_count`, and `notify_on_completion` (boolean, set when admin
  accepts before signup completes -- see [Deferred accepted
  email](#deferred-accepted-email-in-set_session)). The frontend uses
  `registration_token` to look up the current signup state, including
  whether the user is already accepted. Entries expire after 2 weeks
  and are explicitly deleted when `create_user` completes (whichever
  happens first).

### Sync registration

This is an important flow and necessary to migrate existing users. A user
is a full member in VoltaClub, but does not have an account on the website.

1. **Admin imports VoltaClub CSV** -- member data lands in the `sync`
   table.
2. **Admin runs "Accept All New"** -- for each new member, the backend:
   - Creates a `newusers` entry with `accepted=True`, using the name from
     the CSV.
   - Creates a `registration_state` entry (generates a
     `registration_token`, `accepted=True`).
   - Stores their sync data (userdata, birthday, bondsnummer index).
   - Sends a **sync_please_register** email with a signup link:
     `{frontend}/account/signup?token={registration_token}`.
3. **User clicks the link** -- the frontend reads `registration_token` from
   the URL and fetches the `registration_state`. Because `accepted` is
   `True`, the frontend knows this user was already approved and can
   present the page accordingly (e.g. "Welcome, finish setting up your
   account" rather than a generic registration form). The frontend calls
   `renew_signup`, which starts a Faroe signup session. Faroe sends a
   **signup_verification** email with a verification code.
4. **User enters the verification code** -- or clicks the direct link in
   the verification email (which pre-fills the code).
5. **User sets a password.**
6. **Signup completes** -- Faroe finalizes the account by calling
   `create_user`. Because `accepted=True` in `newusers`, the `member`
   permission is granted immediately (1-year TTL) and the `newusers` entry
   is deleted. The user is now a full member.

**Emails sent (2+):**
1. `sync_please_register` -- "Create your account" with signup link (sent
   by the backend when the admin accepts).
2. `signup_verification` -- verification code (sent by Faroe when the user
   starts signup, expires in ~20 min; `renew_signup` sends a fresh one if
   needed).

### Self-registration

A user creates their account on their own via the website. They can log in
immediately, but membership requires admin approval.

1. **User submits the registration form** -- the backend creates a
   `newusers` entry with `accepted=False` (name from the form) and a
   `registration_state` entry (`accepted=False`). It immediately starts a
   Faroe signup session, which sends a **signup_verification** email with a
   verification code. The `signup_token` is stored in `registration_state`.
2. **User enters the verification code** -- or clicks the direct link in
   the verification email. If the Faroe signup session expired before the
   user returned, the frontend calls `renew_signup` to get a fresh session
   and verification email.
3. **User sets a password.**
4. **Signup completes** -- Faroe finalizes the account by calling
   `create_user`. Because `accepted=False` in `newusers`, the account is
   created without the `member` permission. The `newusers` entry is kept
   (not deleted). The user can log in but sees a "pending approval" state
   (detected via `pending_approval` in session info) and cannot access
   member-only areas.
5. **Admin accepts the user** (from the Registrations tab) -- the backend
   grants the `member` permission (1-year TTL), deletes the `newusers`
   entry, and sends an **account_accepted_self** email confirming the
   membership is approved.

After step 5, the user is a full member.

**Emails sent (2+):**
1. `signup_verification` -- sent immediately at registration (may expire;
   `renew_signup` sends a fresh one if needed).
2. `account_accepted_self` -- "Your membership is approved" (sent when the
   admin accepts).

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
   calls back to `/invoke` which triggers `create_user` in `auth.py`.

**Timing constraint:** when `create_signup` is called, Faroe calls back to
the `/email` endpoint *during* the HTTP call (before `signup_token` is
returned to the caller). This means the signup link in the verification
email cannot use `signup_token`. Instead, the email link uses
`registration_token` (which was created earlier and is already known). The
frontend uses `registration_token` to look up the `signup_token` from
`registration_state`.

**Expiry:** Faroe signup sessions expire after approximately 20 minutes. If
the user doesn't complete signup in time, a new signup must be created via
`renew_signup` or `resend_signup_email`.

### Account creation (`create_user` in `auth.py`)

This function is called by Faroe (via `/invoke`) when `complete_signup`
succeeds. It:

1. Checks `users_by_email` -- rejects if email already exists.
2. Checks `newusers` -- rejects if email not found (user must go through
   the newusers flow).
3. Generates a `user_id` from an auto-incrementing counter and the user's
   name (e.g. `0_alice_smith`).
4. Stores user data: `:profile` (firstname, lastname), `:email`,
   `:password`, `:sessions_counter` in the `users` table, and the email
   index in `users_by_email`. The profile name is initially set from the
   `newusers` entry and later updated by `update_existing` from the sync
   CSV (the authoritative source for names).
5. If `accepted=True`: grants `member` permission (1-year TTL) and deletes
   the `newusers` entry.
6. If `accepted=False`: keeps the `newusers` entry for later admin
   approval.
7. Deletes the `registration_state` entry (in both cases). The signup link
   is no longer valid after the account exists.

`create_user` never sends emails. It runs inside the Faroe `/invoke`
callback and must not block on SMTP. Any notification emails are handled
elsewhere (see [Deferred accepted
email](#deferred-accepted-email-in-set_session)).

### Registration scenarios

The two primary flows above can interact in unexpected ways. The following
scenarios describe how the system handles each case. These are not separate
features -- the sync lifecycle and `accept_new` / `accept_user` logic must
handle them as part of their normal processing.

#### Scenario 1: Self-registered, admin accepts BEFORE signup completes

A user registers on the website but doesn't finish their Faroe signup
before the admin reviews the Registrations tab.

1. **User submits registration form** -- `newusers` entry created with
   `accepted=False`, `registration_state` entry created with
   `accepted=False`, Faroe signup started (sends `signup_verification`
   email).
2. **Admin accepts the user** (Registrations tab) -- `accept_user` sets
   `accepted=True` in both `newusers` and `registration_state`. It also
   sets `notify_on_completion=True` in `registration_state`. The
   **account_accepted_self** email is NOT sent yet -- it provides no value
   while the user hasn't finished setting up their account.
3. **User completes signup** -- enters verification code (from step 1 or a
   renewed one), sets password. `create_user` sees `accepted=True` in
   `newusers` -> grants `member` permission and deletes the `newusers`
   entry.
4. **User's first session** -- after signup, the frontend calls
   `/cookies/set_session/`. The `set_session` handler detects
   `notify_on_completion=True` in `registration_state` for this user's
   email, sends the **account_accepted_self** email, and clears the flag
   (see [Deferred accepted email](#deferred-accepted-email-in-set_session)).

This differs from standard self-registration only in timing: the admin
approves before the user finishes. The end result is the same -- the user
is a full member immediately upon completing signup.

#### Scenario 2: Self-registered user appears in sync CSV (no account yet)

A user has self-registered (creating a `newusers` entry with
`accepted=False` and a `registration_state` entry), but before they
complete signup, their email also appears in a sync CSV import.

1. **User submitted registration form earlier** -- `newusers` and
   `registration_state` entries exist with `accepted=False`. Faroe signup
   may or may not still be active.
2. **Admin imports CSV and runs "Accept All"** -- `compute_groups` places
   this email in the `to_accept` group (in `newusers` with
   `accepted=False`). `accept_new` detects the email already exists in
   `newusers` and **updates the entry to `accepted=True`** rather than
   creating a new one. It also populates `userdata`, `birthdays`, and the
   bondsnummer index from the sync data. A **sync_please_register** email
   is sent.
3. **User completes signup** -- either via their original
   `registration_token` or the new link from the sync email. `create_user`
   sees `accepted=True` in `newusers` -> grants `member` permission and
   deletes the `newusers` entry.

The sync effectively "upgrades" the self-registration by marking it as
accepted and populating the member data from the CSV.

#### Scenario 3: Self-registered user appears in sync CSV (already has account)

A user has self-registered and completed signup. They have an account in
the `users` table but `accepted` was `False`, so they have no `member`
permission and the `newusers` entry was kept.

Their email then appears in a sync CSV import. `compute_groups` places this
email in the `to_accept` group (in `users_by_email` AND in `newusers` with
`accepted=False`). When `accept_new` processes the entry:

1. Grants `member` permission (1-year TTL).
2. Deletes the `newusers` entry.
3. Populates `userdata`, `birthdays`, and the bondsnummer index from the
   sync data.
4. Sends an **account_accepted_self** email confirming their membership
   is approved. From the user's perspective the result is the same whether
   acceptance came through sync or was manual.

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

The sync process imports member data from the Atletiekunie's VoltaClub CSV
export and reconciles it with the user database. Every step is explicit and
admin-triggered.

### 1. Import CSV (`import_sync`)

The admin uploads a CSV file. The `sync` table is cleared and repopulated
with parsed entries. Each row becomes a `UserDataEntry` keyed by email.

The CSV uses the VoltaClub "alle velden" format with UTF-8 BOM.
Relevant columns: `Bondsnummer`, `Voornaam`, `Tussenvoegsel`, `Achternaam`,
`Geslacht`, `Geboortedatum`, `Email`, `Club lidmaatschap opzegdatum`.

Rows without an email are skipped. Emails are normalized to lowercase.
Bondsnummer is parsed as an integer.

### 2. Compute groups (`compute_groups`)

Read-only comparison of the `sync` table against the user database. The
groups map directly to admin actions: "Accept" processes `to_accept`,
"Update" processes `existing`, "Remove" processes `departed`.

Returns five groups:

- **to_accept** -- emails in sync that don't yet have full member status.
  This includes:
  - Truly new people (not in `users_by_email`, not in `newusers`, not
    bondsnummer-matched).
  - Self-registered users without an account (in `newusers` with
    `accepted=False`, not in `users_by_email`).
  - Self-registered users with an account but pending approval (in
    `users_by_email` AND in `newusers` with `accepted=False`).

  The common thread: they appear in the sync CSV (proving VoltaClub
  membership) but haven't been accepted yet. "Accept All" handles all of
  them.

- **pending_signup** -- emails in `newusers` with `accepted=True` that are
  not yet in `users_by_email`. These users have already been accepted (by a
  previous "Accept All" or manually) but haven't completed Faroe signup.
  Informational only -- no admin action needed.

- **existing** -- emails in sync that are in `users_by_email` and are NOT
  in `newusers` with `accepted=False` (i.e. they are fully accepted
  members). Includes bondsnummer-matched users whose email changed. Each
  entry pairs the sync data with the current `userdata` (which may be
  `null` if `update_existing` hasn't been run yet for this user).

- **departed** -- registered users (in `users_by_email`) with an active
  `member` permission who are NOT in the active sync set (or have an
  `opzegdatum` cancellation date in the past). Users whose email is being
  changed via bondsnummer matching are not considered departed.

- **email_changes** -- sync entries where the bondsnummer maps to an
  existing user with a different email. Reports `old_email`, `new_email`,
  `bondsnummer`.

System users are excluded from all groups.

Cancelled members (with an `opzegdatum` that is in the past) are treated as
departed even if present in the CSV. A future cancellation date is ignored
until that date has passed.

### 3. Accept (`accept_new`)

The admin reviews the `to_accept` group and triggers "Accept All". For each
entry, `accept_new` determines the appropriate action based on the user's
current state:

**Truly new** (not in `users_by_email`, not in `newusers`):

1. A `newusers` entry is created with `accepted=True`, using the name from
   the sync data.
2. A `registration_state` entry is created (generates a
   `registration_token`).
3. Sync data is stored (`userdata`, `birthdays`, bondsnummer index).
4. A **sync_please_register** email is sent with a link to create their
   account.

**Self-registered, no account yet** (in `newusers` with `accepted=False`,
not in `users_by_email`):

The sync CSV confirms they are a real VoltaClub member, so their
self-registration is upgraded:

1. `newusers` entry is updated to `accepted=True`.
2. Sync data is stored (`userdata`, `birthdays`, bondsnummer index).
3. A **sync_please_register** email is sent.

When the user later completes their Faroe signup, `create_user` sees
`accepted=True` and grants `member` permission immediately. This is
[Scenario 2](#scenario-2-self-registered-user-appears-in-sync-csv-no-account-yet).

**Self-registered, has account** (in `users_by_email` AND in `newusers`
with `accepted=False`):

The user completed signup but was waiting for admin approval. The sync CSV
confirms their membership:

1. `member` permission is granted (1-year TTL).
2. `newusers` entry is deleted.
3. Sync data is stored (`userdata`, `birthdays`, bondsnummer index) and the
   user profile is updated with the authoritative name from the sync CSV.
4. An **account_accepted_self** email is sent.

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
   old_email to new_email (see [Bondsnummer matching](#bondsnummer-matching)).
2. **Sync data is copied to userdata** (`sync_userdata`): the `userdata`
   table is updated with the sync entry.
3. **User profile is updated** (`users:{user_id}:profile`): firstname and
   lastname are updated from the sync data (voornaam, tussenvoegsel +
   achternaam). The sync CSV is the authoritative source for names.
4. **Member permission is renewed** (1-year TTL).
5. **Bondsnummer index is updated.**
6. **Birthday table is updated** with geboortedatum, voornaam,
   tussenvoegsel, achternaam.

Creating an account alone does not populate these tables. The userdata and
birthday tables are first populated by `accept_new` (for new entries) and
subsequently updated by `update_existing` (for existing members each sync
cycle).

### 6. Remove departed (`remove_departed`)

For each departed user, the account is fully deleted:

1. User account is deleted from the `users` table (all fields: profile,
   email, password, sessions_counter, permissions).
2. `users_by_email` index entry is deleted.
3. `userdata` entry is deleted.
4. Birthday entry is deleted.
5. Bondsnummer index entry is deleted.
6. Faroe `delete_user` is called to clean up any auth state.

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

1. `accept_user` sets `notify_on_completion=True` in `registration_state`
   when it accepts a user who has no account yet.
2. After the user completes Faroe signup, the frontend calls
   `/cookies/set_session/`.
3. `set_session` looks up the user's email in `registration_state`. If
   `notify_on_completion=True`, it sends the **account_accepted_self**
   email and clears the flag.

This keeps email sending out of `create_user` (which runs inside Faroe's
`/invoke` callback and must not block on SMTP) and ensures the user
receives the acceptance notification only after their account is fully
ready.

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
- `pending_approval` -- whether the user still has a `newusers` entry
  (accepted=False, waiting for admin)

## Core database tables

| Table | Key | Value | Purpose |
|---|---|---|---|
| `users` | `{user_id}:{field}` | varies | User data: `:profile`, `:email`, `:password`, `:sessions_counter`, `:perm:{name}` |
| `users_by_email` | email | user_id bytes | Email-to-user index |
| `users_by_bondsnummer` | str(bondsnummer) | email bytes | Bondsnummer-to-email index |
| `newusers` | email | JSON `{email, firstname, lastname, accepted}` | Pre-registration holding table |
| `registration_state` | registration_token | JSON `{email, accepted, signup_token, email_send_count, notify_on_completion}` | Tracks signup progress (2-week TTL, deleted on account creation) |
| `metadata` | key | value | Global counters (e.g. `user_id_counter`) |
| `userdata` | email | JSON `UserDataEntry` | Member data from sync |
| `sync` | email | JSON `UserDataEntry` | Imported CSV data (replaced each import) |
| `system_users` | email | `b"1"` | Users excluded from sync comparison |

## Permission system

Permissions are stored as separate keys in the `users` table:

    Key:   {user_id}:perm:{permission_name}
    Value: b""
    TTL:   1 year from grant (expires_at = timestamp + 365 days)

The storage layer filters expired entries automatically when `timestamp` is
passed to `store.get()`.

**Core permissions:**

- `member` -- grants access to member-only areas (Leden pages, birthdays).
  Granted at signup (when accepted) and renewed by `update_existing` each
  sync cycle.
- `admin` -- grants access to the admin panel and all admin API routes.

**Role permissions:** committee/group tags (`bestuur`, `comcom`, `batcie`,
etc.) with no special system behavior. Managed manually by admins and can be
used in future features.

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
matching, this would incorrectly show as one departed + one new member.

### How it works

1. When `sync_userdata` or `add_accepted` runs, the bondsnummer index
   (`users_by_bondsnummer` table) is populated: `str(bondsnummer)` ->
   email.
2. `compute_groups` calls `detect_email_changes` which checks each sync
   entry's bondsnummer against the index. If a bondsnummer maps to a
   different email, it's reported as an `email_change`.
3. Bondsnummer-matched entries are treated as "existing" (not "new"), and
   the old email is not marked "departed".
4. `update_existing` applies email changes before syncing userdata. The
   `update_user_email` function migrates all references:
   - `users_by_email`: delete old, add new
   - `users:{user_id}:email`: update to new email
   - `userdata`: delete old key, insert new key
   - `users_by_bondsnummer`: update to new email
   - `newusers`: migrate key if exists
   - `registration_state`: update email field if exists
   - `birthdays`: migrate key if exists

The bondsnummer index is deleted when a user departs (via
`remove_departed`), along with the rest of their account data. If a
departed member returns in a future CSV, they are treated as a new member.

## Email notifications

All emails are sent via SMTP with STARTTLS (or saved to the `emails/`
directory when SMTP is disabled). Each email has both a plaintext and HTML
version.

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

Sent when the admin runs "Accept All New" for sync-imported members.

- **Subject:** "Maak je Dodeka account aan"
- **Content:** tells the user their registration with D.S.A.V. Dodeka is
  complete and invites them to create a website account for access to the
  member portal, training schedules, events, etc. Includes a link to
  `{frontend}/account/signup?token={registration_token}`.
- **Purpose:** the first email the user receives from Dodeka, confirming
  their club registration and asking them to set up a website account.
- **Sent by:** Python backend (`do_accept_new_with_email` in `private.py`).

### Email: `account_accepted_self`

Sent when a self-registered user's membership is approved. This can happen
in three ways:

1. The admin manually accepts from the Registrations tab (after the user
   has completed signup) -- sent by `accept_user_handler`.
2. `accept_new` detects a self-registered user who already has an account
   in the sync CSV -- sent by `accept_new` (see
   [Scenario 3](#scenario-3-self-registered-user-appears-in-sync-csv-already-has-account)).
3. The user completes signup after being pre-accepted by the admin -- sent
   by `set_session` on the user's first session (see [Deferred accepted
   email](#deferred-accepted-email-in-set_session) and
   [Scenario 1](#scenario-1-self-registered-admin-accepts-before-signup-completes)).

- **Subject:** "Je lidmaatschap bij Dodeka is goedgekeurd"
- **Content:** tells the user their membership has been approved. Links to
  the homepage.
- **Purpose:** the user already initiated registration themselves. This
  confirms their membership is approved.
- **Sent by:** Python backend (`accept_user_handler` in `app.py`,
  `accept_new` in `sync.py`, or `set_session` in `app.py`).

### Email: `signup_verification`

Sent by Faroe when `create_signup` is called.

- **Subject:** "Activeer je Dodeka account"
- **Content:** "Je verificatiecode is: {code}" with a link to
  `{frontend}/account/signup?token={registration_token}&code={code}`.
- **Purpose:** email address verification. The code must be entered on the
  signup page to prove email ownership.
- **Expires:** ~20 minutes (Faroe signup session lifetime).
- **Link construction:** the Python `/email` handler looks up
  `registration_token` by email and constructs the link. The
  `registration_token` is used (not `signup_token`) because of the timing
  constraint described in [Faroe signup flow](#faroe-signup-flow).
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

- **`board_setup`:** one-time creation. Prepares as accepted user, marks as
  system user, initiates Faroe signup.
- **`board_renew`:** yearly renewal when the board rotates. Triggers
  password reset and renews admin permission.

### Permission management

Admins can manage permissions via:

- `POST /admin/add_permission/` -- add a single permission (except admin)
- `POST /admin/remove_permission/` -- remove a single permission
- `POST /admin/set_permissions/` -- declaratively set permissions for
  multiple users (add missing, remove extra, never touches admin permission)

The `admin` permission cannot be added through the public API. It can only
be granted via the `grant_admin` private command.
