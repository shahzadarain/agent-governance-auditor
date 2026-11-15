"""Human approval tokens bound to one exact action.

A token is an HMAC over: the actor the approval is for, the approver, the
decision, the action name, a digest of the parameters, the expiry time, and a
single-use nonce. Changing any of these breaks the signature. A used nonce is
remembered, so a token cannot be replayed.
"""

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass


class ApprovalError(PermissionError):
    pass


def params_digest(params):
    canonical = json.dumps(params, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class ApprovalToken:
    actor: str
    approver: str
    decision: str
    action: str
    params_digest: str
    expires_at: float
    nonce: str
    signature: str


class ApprovalService:
    def __init__(self, key, clock=time.time):
        if not key:
            raise ValueError("an approval signing key is required")
        self._key = key
        self._clock = clock
        self._used_nonces = set()

    def _mac(self, actor, approver, decision, action, digest, expires_at, nonce):
        message = "\n".join([actor, approver, decision, action, digest, repr(float(expires_at)), nonce])
        return hmac.new(self._key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    def record_decision(self, *, actor, approver, action, params, approved=False, ttl_seconds=300):
        """Called by the human approval channel, never by the agent."""
        decision = "approved" if approved else "denied"
        digest = params_digest(params)
        expires_at = self._clock() + ttl_seconds
        nonce = os.urandom(16).hex()
        signature = self._mac(actor, approver, decision, action, digest, expires_at, nonce)
        return ApprovalToken(actor, approver, decision, action, digest, expires_at, nonce, signature)

    def verify_approval(self, token, *, actor, action, params):
        if token is None:
            raise ApprovalError("approval missing")
        expected = self._mac(token.actor, token.approver, token.decision, token.action,
                             token.params_digest, token.expires_at, token.nonce)
        if not hmac.compare_digest(expected, token.signature):
            raise ApprovalError("approval signature is not valid")
        if token.decision != "approved":
            raise ApprovalError("approval was denied")
        if token.actor != actor or token.action != action:
            raise ApprovalError("approval is for a different actor or action")
        if token.params_digest != params_digest(params):
            raise ApprovalError("approval is for different parameters")
        if self._clock() >= token.expires_at:
            raise ApprovalError("approval expired")
        if token.nonce in self._used_nonces:
            raise ApprovalError("approval was already used")
        self._used_nonces.add(token.nonce)
        return True
