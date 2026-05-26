# Admin cleanup and sync safety

Design for admin management improvements and sync safety guards.

## 1. Manual cleanup of registrations and users

The sync only manages people with a bondsnummer. Two categories fall
outside its scope:

- **Departed registrations** — accepted and linked to a bondsnummer,
  but the person never completed signup and their bondsnummer later
  disappeared from the import. See `required-spec-updates.md` item 5.
- **Unlinked accepted people** — accepted by the admin on the site but
  never appeared in any sync (no bondsnummer). May even have completed
  signup, becoming a live user with no bondsnummer.

Rather than adding complexity to the sync flow, these are handled by
giving admins direct management actions:

### Delete registration

New admin action on the registrations page. Permanently removes a
registration. Available for any registration regardless of state.

### Delete user

New admin action on the users page. Removes a live user account (same
cleanup as `remove_departed_users`: deletes profile, email, password,
disabled flag, sessions counter, email index, member permission, and
bondsnummer link if any).

These keep the sync unchanged — its most complex part — and give admins
the tools to clean up edge cases manually when they notice them.

## 2. Sync confirmation modal

A single confirmation modal before destructive sync actions. The modal
accumulates reasons and presents them together — the admin confirms
once, not per-reason.

### Triggers

The modal appears when the admin clicks "Complete sync" and any of the
following are true:

1. **Stale file** — the imported file is older than 1 day (see file
   date tracking below)
2. **Departures** — there are any departed members in the sync status

When none of these triggers apply, "Complete sync" proceeds immediately
without a modal.

### Modal content

The modal lists every applicable reason as a warning, for example:

> **Confirm sync completion**
>
> - The imported file is from 28 March 2026 (10 days ago). Members who
>   joined after this date will appear as departed.
> - 3 member accounts will be removed (departed members).
>
> Are you sure you want to complete this sync?
>
> [Cancel] [Complete sync]

Each reason is a bullet. The wording is specific: it includes the file
date and count of departures, not generic warnings. If only one trigger
fires, only that bullet appears.

### Implementation

This is entirely frontend logic. The backend does not change — the
modal just gates the `complete_sync` call. The frontend checks the
sync status response before calling `complete_sync`:

```
const reasons: string[] = [];
if (fileAge > 86400) reasons.push(`The imported file is from ...`);
if (departed.length > 0) reasons.push(`${departed.length} member accounts ...`);
if (reasons.length > 0) showConfirmModal(reasons);
else completeSync();
```

## 3. File date tracking

The Atletiekunie CSV has no export timestamp. We capture the file's
filesystem modification time to give the admin visibility into how
current the data is.

### Frontend

Read `file.lastModified` (milliseconds, from the browser File API)
when the admin selects a file. Send it with the import request as
`file_modified_at` (integer, seconds since epoch).

### Backend

- `import_sync` accepts optional `file_modified_at` integer
- Store in sync state (the JSON blob in `sync_state` table)
- `sync_status` returns `file_modified_at` when a session is active
  (null when no session or not provided)

### Display

Always show the file date prominently in the sync status area when a
session is active, e.g. "Imported file from: 3 April 2026". This is
shown regardless of age — the admin should always know what they're
working with.

The confirmation modal (section 2) uses the 1-day threshold to decide
whether to warn.

`File.lastModified` is the OS modification time, which is usually the
download time. It can differ for copied files, but it's the best
signal available without server-side changes to the Atletiekunie export.

## Implementation order

1. Add delete registration endpoint + frontend button
2. Add delete user endpoint + frontend button
3. Add `file_modified_at` to import flow (frontend + backend)
4. Add confirmation modal to "Complete sync" button
