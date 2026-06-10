# Design Decisions

## Decision 1

Permission boundary attached during CreateRole.

Reason:
Avoid race condition between role creation and boundary attachment.

---

## Decision 2

Trust principals restricted to approved AWS services.

Reason:
Prevents confused deputy and cross-account trust abuse.

---

## Decision 3

SCP blocks CreateRole outside vending machine.

Reason:
Prevents bypass of mandatory controls.

---

## Decision 4

sts:AssumeRole not globally denied.

Reason:
Required for legitimate AWS service integrations.

Blanket deny creates operational burden.

Scoped controls preferred.
