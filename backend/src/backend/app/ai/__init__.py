"""The AI harness lives inside the platform (D18): same process, same Session.

Acting is the exception — the field agent loop runs in Shauron (§6b) and reaches the
model only through the platform. Everything in this package is the *knowing* half:
catalog, execution, planning, context assembly.
"""
