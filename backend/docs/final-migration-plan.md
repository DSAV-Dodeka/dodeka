# Final Migration Plan

This is the implementation handoff for bringing the backend in line with
[`spec.md`](./spec.md). `spec.md` is authoritative; this file describes the
rough code changes needed to reach it from the current implementation.

## Final Target

The final model has three clean identities:

- `registration_id` for pending registrations
- `user_id` for live accounts
- `bondsnummer` for all Volta-managed data

The final design also has two clean data domains:

- **Dodeka-managed data** keyed by `registration_id` or `user_id`
- **Volta-managed data** keyed only by `bondsnummer`

This is the core simplification. Sync should reason through `bondsnummer`, not
through mutable email.

## Current Starting Point

The current implementation is still centered on normalized email:

- `registrations` is keyed by normalized email
- `registration_tokens` maps stable public token to normalized email
- registration rows still carry `account_created` and `notify_on_completion`
- `request_registration` immediately starts Faroe signup and returns both
  `registration_token` and `signup_token`
- `session_info` still exposes `pending_approval`
- `sync`, `userdata`, and several derived tables are keyed by email
- `users_by_bondsnummer` still maps `bondsnummer -> email`
- sync preview still returns `to_accept`, `pending_signup`, `existing`,
  `email_changes`, and `departed`
- the admin/frontend flow still assumes:
  - `/admin/list_newusers/`
  - `/admin/accept_user/`
  - `/admin/resend_signup_email/`
  - `/admin/accept_new_sync/`

The final design removes those email-centered lifecycle assumptions.

## Main Design Changes

1. Pending registrations become simpler
   - no “account created but still pending approval” registration state
   - only accepted registrations may start Faroe signup
2. Live users become simpler
   - always have verified email
   - may or may not already have `bondsnummer`
3. Volta data becomes its own domain
   - current imported snapshot keyed by `bondsnummer`
   - current applied Volta data keyed by `bondsnummer`
4. Unresolved sync rows no longer auto-bind by email
   - backend returns candidates
   - frontend posts the chosen outcome explicitly
   - admin confirms matches explicitly
5. Pending registrations with `bondsnummer` follow the current Volta email
   - live users do not

In practice, this means replacing:

- email-keyed canonical registration rows with `registration_id`-keyed rows
- email-keyed sync identity with bondsnummer-keyed Volta state
- bulk “accept new sync users by email” with explicit review and matching
- pending-approval live users with accepted pending registrations only

## Backend Areas To Change

### `src/apiserver/data/registrations.py`

This module should move to the final pending-registration model.

Required changes:

- replace canonical storage `registrations[email]` with
  `registrations[registration_id]`
- replace `registration_tokens[registration_token] -> email` with:
  - `registrations_by_email[email] -> registration_id`
  - `registrations_by_bondsnummer[bondsnummer] -> registration_id`
- rename the public concept `registration_token` to `registration_id`
- remove `account_created`
- remove `notify_on_completion`
- make `signup_token` a resumable Faroe-session handle on the pending
  registration row, not part of a multi-stage registration lifecycle

The row should represent only a pending registration. On successful signup, it
should be deleted.

### `src/apiserver/data/auth.py`

This is the main Faroe integration rewrite.

Required changes:

- `create_user()` must require an accepted pending registration
- it must delete the registration row after creating the live user
- it must link `users_by_bondsnummer` when the registration has a
  `bondsnummer`
- it must grant `member` immediately
- current `update_user_email_address()` should remain the only live-user email
  mutation path
- remove code paths that keep a registration row around after successful signup

`update_user_email_address()` must remain the only place where a live user’s
verified account email changes.

### `src/apiserver/data/userdata.py` And Related Sync-Derived Tables

This module should stop being the core sync identity store.

The final model needs a dedicated Volta-data module keyed by `bondsnummer`.
Current email-keyed helpers should either:

- be removed, or
- be reduced to feature-specific derived projections

The identity source of truth must move to:

- imported snapshot by `bondsnummer`
- applied Volta data by `bondsnummer`

This includes the current email-keyed `userdata` storage and any other
identity-bearing tables populated directly from sync.

### `src/apiserver/data/features/birthdays.py`

Birthday handling should stop being baked into the core identity model.

If the birthdays feature remains, it should become a derived read model from
Volta-managed data rather than a special identity-bearing table.

### `src/apiserver/sync.py`

This is the largest rewrite.

Required changes:

- import a pending snapshot keyed by `bondsnummer`
- keep current applied Volta-managed data keyed by `bondsnummer`
- validate unique `bondsnummer` and unique normalized email per import
- do not add `sync_by_email`
- stop auto-binding unresolved rows by email
- produce `review_required` items with explicit candidate matches
- support admin-confirmed outcomes:
  - match registration
  - match live user
  - no match -> create new accepted registration

Matching rules must become:

1. existing `users_by_bondsnummer`
2. existing `registrations_by_bondsnummer`
3. review-required candidates among unlinked registrations and unlinked users

Candidate generation should be implemented as a fixed algorithm, not as an
open-ended fuzzy matcher:

- candidate pool:
  - live users without `bondsnummer`
  - pending registrations without `bondsnummer`
- derived keys:
  - normalized email
  - normalized full name
  - normalized surname
  - given-name prefix key (first four normalized characters)
- rules:
  1. exact email -> `email_exact`
  2. exact full name -> `name_exact`
  3. same surname + same given-name prefix key -> `name_partial`
- deduplicate by subject
- sort by strongest reason, then number of reasons descending, then
  `registration` before `user`, then `subject_id`
- return at most five candidates

The current groups and route semantics should be replaced as follows:

- current `to_accept` / `/admin/accept_new_sync/` bulk flow:
  - split into `review_required` plus explicit `resolve_sync_match`
- current `pending_signup`:
  - replace with `linked_registrations`
- current `email_changes`:
  - stop surfacing as a separate top-level group
  - represent pending-registration rewrites inside `linked_registrations`
  - represent live-user Volta/account differences through `volta_data` and
    generic field diffs
- current `existing`:
  - keep as linked live users only
- current `departed`:
  - keep, but only for linked live users

Pending registration email behavior must become:

- if a registration already has `bondsnummer`, sync may rewrite its email to
  the current Volta email
- when that happens, clear stale Faroe signup state and send a fresh invite

Live user email behavior must become:

- sync never rewrites it
- mismatches are informational only

Departure behavior must become:

- only live users with `bondsnummer` are eligible for automatic departed
  handling

The sync preview payload must also become richer:

- `review_required`
- `linked_registrations`
- `existing`
- `departed`
- generic `field_diffs`

`update_existing` must apply both kinds of already-linked rows:

- linked pending registrations by rewriting stale registration email and
  restarting signup when needed
- linked live users by refreshing derived Dodeka-owned projections and
  renewing `member`

### Public/Auth Handlers

Files:

- `src/apiserver/handlers/auth.py`
- `src/apiserver/handlers/admin.py`
- `src/apiserver/private.py`
- `src/apiserver/app.py`

Required changes:

- `request_registration` should create only a pending registration, not start
  Faroe signup
- reusing an existing pending registration must not clear `accepted`,
  `bondsnummer`, or current signup state
- `/auth/request_registration` should stop returning `signup_token`
- `registration_status` / `renew_signup` should work by `registration_id`
- `/auth/registration_status` should return the current `signup_token` when
  active, otherwise `null`
- `/auth/renew_signup` should return the fresh current `signup_token`
- `renew_signup` must require `accepted=True`
- `/auth/registration_status` should stop returning `account_created`
- invite links and signup links should use `registration_id`
- remove old deferred-acceptance / post-signup pending-approval behavior
- add admin endpoints for:
  - `list_registrations`
  - `accept_registration`
  - `resolve_sync_match`
  - `link_bondsnummer`
- `/admin/list_newusers/` should be removed or replaced by
  `/admin/list_registrations/`
- `/admin/accept_user/` should be replaced by `accept_registration`
- `/admin/resend_signup_email/` should either be removed or reduced to a thin
  wrapper around the final accepted-registration flow
- `/admin/accept_new_sync/` should be replaced by explicit per-row
  `resolve_sync_match`
- keep `/email` resolving current `registration_id` through
  `registrations_by_email`

### Sessions And User Info

Files:

- `src/apiserver/server.py`
- `src/apiserver/data/user.py`
- `src/apiserver/handlers/auth.py`

Required changes:

- remove `pending_approval` from the core account lifecycle
- `/auth/session_info/` should stop returning `pending_approval`
- remove any code that depends on a surviving registration row after live user
  creation
- keep session validation reloading current user state after cached session
  validation

### Volta Data Module

The final model needs a dedicated module for Volta-managed data.

It should own:

- pending imported snapshot keyed by `bondsnummer`
- current applied Volta data keyed by `bondsnummer`
- generic Volta field diffing

This may reuse part of the current sync/userdata code, but the final API should
be bondsnummer-based, not email-based.

### Tooling And Private Commands

Files:

- `src/apiserver/private.py`
- `src/apiserver/tooling/commands.py`
- `src/apiserver/tooling/command_handlers.py`

Required changes:

- update private sync commands to the final preview/apply semantics
- remove assumptions that sync groups are only `to_accept`, `existing`, and
  `departed`
- update CLI/debug output to the final `review_required` /
  `linked_registrations` / `existing` / `departed` shape

## Admin Read Models

The backend should expose these read models explicitly:

- `AdminUserRecord`
- `AdminRegistrationRecord`
- `SyncMatchCandidate`
- `SyncReviewItem`
- `PendingRegistrationSyncRecord`
- `ExistingSyncRecord`
- `VoltaFieldDiff`

This matters because the frontend must be able to show:

- current linked Volta data in admin overviews
- exact sync diffs generically, not only name and birthday
- pending-registration email rewrites before apply
- candidate matches that require explicit admin confirmation

At minimum, admin handlers should expose:

- `list_users -> AdminUserRecord[]`
- `list_registrations -> AdminRegistrationRecord[]`
- `sync_status -> SyncStatus`

Compared to the current implementation, this means:

- `list_users` must be enriched with `bondsnummer` and `volta_data`
- `list_newusers` must become `list_registrations`
- `sync_status` must stop returning the current `to_accept` /
  `pending_signup` / `email_changes` shape

## Frontend Areas To Change

### Registration Flow

Files:

- `dodekafrontend/src/functions/backend.ts`
- `dodekafrontend/src/functions/query.ts`
- `dodekafrontend/src/components/PendingRegistrations.tsx`
- `dodekafrontend/src/pages/account/register/register-logic.ts`
- `dodekafrontend/src/pages/account/signup/signup.tsx`
- `dodekafrontend/src/pages/flow-test/RegisterFlow.tsx`

Required changes:

- `requestRegistration()` no longer immediately enters signup
- the invite email becomes the primary entry point into signup
- `registration_id` replaces `registration_token`
- the frontend registration state must stop depending on immediate
  `signup_token` availability from `requestRegistration()`
- signup flow begins only after `accepted=True`

### Admin Registrations And Users UI

Files:

- `dodekafrontend/src/functions/backend.ts`
- `dodekafrontend/src/functions/query.ts`
- `dodekafrontend/src/pages/account/profile/profile.tsx`
- `dodekafrontend/src/functions/debug-user.ts`
- `dodekafrontend/src/pages/admin/admin.tsx`

Required changes:

- replace `list_newusers` semantics with richer pending-registration records
- extend the users overview to show linked Volta data
- show linked `bondsnummer` on both registrations and users
- expose explicit `link_bondsnummer`
- remove UX built around:
  - `has_signup_token`
  - `is_registered`
  - `pending_approval`

### Admin Sync UI

Files:

- `dodekafrontend/src/functions/backend.ts`
- `dodekafrontend/src/functions/query.ts`
- `dodekafrontend/src/pages/admin/admin.tsx`

Required changes:

- stop assuming unresolved rows can be auto-accepted by email
- add a `review_required` section with explicit candidate choices
- add a `linked_registrations` section for pending registrations already linked
  by `bondsnummer`
- render generic Volta field diffs, not hardcoded name/birthday checks
- show current applied Volta data and incoming imported Volta data
- keep single-row sync actions keyed by `bondsnummer`
- replace the current summary/count model based on:
  - `to_accept`
  - `pending_signup`
  - `email_changes`

## Tests To Rewrite

The most important updates will be in:

- `tests/test_registration.py`
- `tests/test_faroe_api.py`
- `tests/test_sync.py`
- `tests/test_spec.py`

New tests should cover:

- self-registration creating only a pending unaccepted registration
- accepted registration entering Faroe signup only after invite / renew
- confirmed sync match linking a registration by `bondsnummer`
- confirmed sync match linking a live user by `bondsnummer`
- sync preview showing linked pending registrations separately from live users
- pending registration email rewrite when a linked Volta email changes
- live user email staying unchanged when a linked Volta email changes
- explicit candidate-based sync review
- strict import validation for duplicate `bondsnummer` / duplicate email
- departed handling only for linked live users

## Suggested Implementation Order

1. Simplify registration lifecycle around accepted pending registrations only
2. Introduce the final bondsnummer-keyed Volta data module
3. Rewrite sync matching and review around explicit candidates
4. Rewrite live-user creation to consume and delete accepted registrations
5. Update admin read models
6. Update frontend registration flow
7. Update frontend admin sync flow
8. Rewrite tests

## Notes

- [`spec.md`](./spec.md) is the implementation target.
- [`registration-key-options.md`](./registration-key-options.md) remains the
  rationale/comparison document.
