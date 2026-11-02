# Multi-factor and SSO

Two different things that are often asked for together:

| | What it is | Who turns it on |
|---|---|---|
| **TOTP second factor** | a 6-digit code from an authenticator app, on top of the password | each user, for their own account |
| **SSO (OIDC)** | the identity provider authenticates the person (Google, Microsoft, Okta…) | the deployment, through environment variables |

They compose: a user with MFA who signs in through Google still gets the code
prompt.

## TOTP, per user (optional)

`Administration → My security` (`/api/v1/auth/mfa…`). It is **never** enabled by
an administrator on someone else's behalf — an account locked behind a factor
its owner did not set up is a support incident, not a security win.

Enrolment is a handshake:

1. `POST /api/v1/auth/mfa/enroll` with the current password → returns the secret
   and an `otpauth://` URI. The screen renders it as a QR **and** as text.
2. `POST /api/v1/auth/mfa/activate` with a code from the app → the factor becomes
   required and eight recovery codes are returned **once**.

Until step 2 the account behaves exactly as before, so abandoning the screen is
safe. After that, `POST /api/v1/auth/login` answers
`{"mfa_required": true, "challenge": "…"}` instead of a session, and
`POST /api/v1/auth/mfa/verify` exchanges the challenge (plus a TOTP or a recovery
code) for one. A challenge lives 5 minutes and dies after 5 wrong attempts.

Turning it off (`POST /mfa/disable`) requires a current code or a recovery code.
Recovery codes are single-use and stored as SHA-256 hashes; rotating them
invalidates the previous set.

Implementation notes: RFC 6238 over RFC 4226, HMAC-SHA1, 30-second steps, 6
digits, ±1 step tolerance (`backend/app/mfa.py`). No third-party crypto, no
external service.

## SSO with Google (or any OIDC provider)

The deployment sets:

```
OIDC_ISSUER=https://accounts.google.com
OIDC_CLIENT_ID=…apps.googleusercontent.com
OIDC_CLIENT_SECRET=…
OIDC_REDIRECT_URI=https://barad.example.com/api/v1/auth/oidc/callback
# OIDC_AUTO_PROVISION=true   # only if you really want JIT accounts
```

In Google Cloud Console: create an **OAuth client (Web application)** with that
redirect URI. No scopes beyond `openid email profile` are needed.

The login screen shows **Continue with Google** only when
`GET /api/v1/auth/oidc/status` reports `configured: true`, and it asks for the
organization slug first, because a person can belong to more than one workspace.

**Pre-registered users only** is the default: if the identity provider vouches
for an address that has no account in the workspace, the callback answers 403
and creates nothing. `OIDC_AUTO_PROVISION=true` flips that to just-in-time
provisioning with the `viewer` role — a deliberate deployment decision, not a
default.

SSO users have no password (`password_hash` is null); they cannot use the
password form, and password reset does not apply to them.

## What is not included

- WebAuthn / passkeys, and SMS as a factor.
- Organisation-wide policy ("everyone in this workspace must use MFA"). The
  pieces exist (the `totp_enabled_at` column is per user), the policy switch
  does not; it belongs with access groups.
- IdP-initiated flows and SCIM provisioning.
