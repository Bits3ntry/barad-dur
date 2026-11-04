/* One vocabulary for the four roles, everywhere the console names them.

   The API keeps `viewer`/`analyst`/`admin`/`owner` — those values are the
   contract. The console shows Viewer / Member / Administrator / Owner, the
   same words the onboarding role table uses. Never render the raw value in a
   sentence a person reads. */
export const ROLE_LABELS = {
  owner: 'Owner',
  admin: 'Administrator',
  analyst: 'Member',
  viewer: 'Viewer',
}

export const ROLE_ORDER = ['owner', 'admin', 'analyst', 'viewer']

export function roleLabel(value) {
  return ROLE_LABELS[value] || value
}
