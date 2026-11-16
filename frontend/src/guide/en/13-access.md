Who can do what, how people get in, and how every decision ends up in a record.

### The four roles

| Role (as printed) | API value | Can |
|---|---|---|
| **Owner** | `owner` | everything, including the workspace itself |
| **Administrator** | `admin` | administrative actions: members, grants, policies, delivery |
| **Member** | `analyst` | read and write the working set: triage, projects, runs |
| **Viewer** | `viewer` | read only — every write is refused by the API, not hidden by the UI |

The console shows the printed names; the API keeps the raw values, because they are a contract. A viewer never sees a disabled button pretending to be a permission: the button works or the request is refused with a sentence naming the role.

**API keys are not a role.** A key authenticates as the workspace owner and bypasses the role checks entirely. If you need a limited consumer, that has to be a person's account — or a purpose-built allowlist on the surface the consumer calls.

**Worker tokens are narrower than keys.** A worker token may only claim, start and report its own jobs; it cannot read the estate.

### Getting people in

- **Invitations** (Settings → Members) are single-use links bound to one email and one role. The link resolves to `/invite` and shows only that seat: organization name, role, the email it was issued to.
- **Email delivery** needs Settings → Delivery to be configured. When it is not, the screen gives you the invite URL to hand over directly — it does not pretend the mail was sent.
- **Creating an account directly** is for the cases where email is not the channel: same screen, same roles.
- **The last owner cannot be demoted or removed.** That is a guard, not a bug report.

### Sign-in security

| Mechanism | Where it is configured | Notes |
|---|---|---|
| password | per person, Settings → Account | the recovery link arrives by mail; an admin can hand over the manual link code |
| multi-factor (TOTP) | Settings → My security | recovery codes are shown once — store them |
| SSO | deployment (`OIDC` settings) | the sign-in screen requires the organization slug before it can call the provider |
| device flow (Shauron) | `shauron login` | approved by a person at `#activate::<code>`; an API key may not approve one |

### The audit trail

Every security-relevant action is written to one ledger, chained per organization (`chain_position`, `prev_hash`, `hash`), which is what makes tampering visible rather than merely unlikely.

What lands there: keys created and revoked, grants approved and widened, role changes, members invited and removed, policy edits (written as the **delta** — `per_zone 2 -> 3`, not "policy updated"), and run decisions.

What does not: page views. The ledger is a record of changes, not a session log.

### When someone leaves

1. Remove the membership (Settings → Members) — this ends sessions on the next authenticated call.
2. Revoke any key that was issued for them or for a consumer they owned (Settings → Service identities).
3. Read the last entries in the **Audit trail** for that identity to see what they touched.
4. If a credential they could read was used anywhere, rotate it — deleting a file does not revoke a key, and git history keeps it.

### Separation that is worth keeping

- The person who **declares** a target is not necessarily the person who **approves** the grant. The product is built around that split; collapsing it into one person is a policy decision, and it should be a conscious one.
- The person who **pentests** a target can be subject to a different approval than the person who runs recon. Red team is re-checked even behind an administrative override.
- The person who **triages** a finding is recorded per finding, per decision, so "who said this was a false positive" survives staff turnover.
