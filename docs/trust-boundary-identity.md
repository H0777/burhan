# Institutional Trust Boundaries & Identity Lifecycle

**Specification:** Specification §4, §5, §7, §8 | Requirements: R01, R03, R09, R10  
**Phase:** Phase 2 (Task T13)  
**Status:** Implemented & Verified  

---

## 1. Architectural Trust Boundaries

The Iraq Cyber-Forensic Auditing System establishes strict trust boundaries separating identity proofing, tenant scoping, cryptographic wallet authorization, and immutable on-chain record keeping:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Institutional Identity Provider (IdP)                    │
│    • Authoritative source of human identity & tenant scope  │
│    • Issues RS256-signed JWTs with sub, iss, aud, claims    │
└──────────────────────────────┬──────────────────────────────┘
                               │ Bearer JWT (Authorization header)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Backend API Service (FastAPI Tenant Context)             │
│    • Verifies JWT against institutional JWKS keys           │
│    • Extracts and locks immutable TenantContext             │
│    • Issues single-use SIWE (EIP-4361) wallet challenges    │
│    • Verifies EIP-191 signatures and enforces tenant bounds │
└──────────────────────────────┬──────────────────────────────┘
                               │ Authorized EVM Address & Generation
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. On-Chain Governance (RoleManager & MultiSigApproval)     │
│    • Tracks participant enrollment and authorization gen    │
│    • Validates signatures & prevents stale vote resurrection│
│    • Enforces multi-party approval and segregation of duties│
└─────────────────────────────────────────────────────────────┘
```

### Key Security Invariants:
1. **Zero Client-Supplied Tenant Authority:**  
   The `institution_id` is never accepted from unverified request headers or JSON request bodies. It is derived strictly from the cryptographically verified OIDC JWT token.
2. **Strict Cross-Tenant Rejection:**  
   If an authenticated caller belonging to Tenant A attempts to sign, verify, or access resources of Tenant B, the operation is immediately rejected (`Tenant context mismatch`).
3. **Single-Use SIWE Nonces:**  
   Wallet challenges are single-use with a strictly enforced 5-minute TTL. Any replay of an already-used or expired challenge returns HTTP 400.
4. **No Private Key Ingestion:**  
   Private keys never leave the participant's hardware wallet or Web3 provider. The backend only handles public addresses and recovers signers from EIP-191 message signatures.

---

## 2. Participant Enrollment & Wallet Binding Procedure

### Step 1: Institutional Authentication
The user authenticates with the Central Bank / Institutional OpenID Connect (OIDC) Identity Provider using OAuth 2.0 Authorization Code with PKCE.
- The IdP provides a verified RS256 token containing:
  - `sub`: Unique user subject identifier.
  - `institution_id`: Institutional tenant code (e.g. `INST-CBI-IQ-01`).
  - `role`: Role assignment (`SUPER_ADMIN`, `AUDITOR`, `OPERATOR`, `REGULATOR`).
  - `permissions`: Scoped capabilities.

### Step 2: SIWE Wallet Challenge Request
The frontend client requests a single-use Sign-In with Ethereum challenge:
- Endpoint: `POST /api/v2/wallet/challenge`
- Payload:
  ```json
  {
    "wallet_address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "chain_id": 31337
  }
  ```
- Response:
  ```json
  {
    "challenge_id": "8fa8d39a-c15b-4357-9db0-f5a04469ce0a",
    "nonce": "7c82a466a9d187cf8e1bb380536c4b22",
    "message": "iraq-aml-audit.cbi.iq wants you to sign in with your Ethereum account: ...",
    "expires_at": "2026-10-23T11:05:00.000Z"
  }
  ```

### Step 3: Signature & Binding Establishment
The participant signs the message using their authorized Web3 institutional signer:
- Signature format: EIP-191 standard (`\x19Ethereum Signed Message:\n` prefix).
- Verification Endpoint: `POST /api/v2/wallet/verify`
- Payload:
  ```json
  {
    "challenge_id": "8fa8d39a-c15b-4357-9db0-f5a04469ce0a",
    "signature": "0x..."
  }
  ```
- Outcome:
  - Signer address is recovered using `eth_account.Account.recover_message`.
  - Signer address is compared against the challenged address.
  - Institutional tenant scoping is validated.
  - Challenge is marked as consumed.
  - `authorization_generation` is initialized to `1` (or incremented upon rotation).

---

## 3. Wallet Rotation & Role Revocation Lifecycle

### Wallet Rotation Procedure
When a participant needs to rotate their physical hardware wallet or security key:
1. The participant authenticates via OIDC.
2. A new SIWE challenge is issued for the *new* wallet address.
3. The new wallet signs the challenge and submits verification.
4. **Authorization Generation Invalidation:**
   - The backend increments `authorization_generation` from `N` to `N + 1`.
   - The on-chain `RoleManager` record is updated via MultiSig governance proposal.
   - Any prior pending proposals or votes signed under generation `N` are automatically invalidated and cannot be executed under generation `N + 1`.

### Role Revocation Procedure
1. If a participant's role is revoked or modified:
   - The OIDC IdP marks the user account inactive or changes the role claim.
   - The backend immediately drops authorization generation validity for the active binding.
   - In `RoleManager.sol`, `assignRole` or `revokeRole` automatically increments `_generations[target]`.
2. **Re-enrollment Protection:**  
   If a revoked participant is subsequently re-granted a role, their generation is incremented again. Old votes and historical actions are preserved in the immutable audit trail but cannot be retroactively used to approve pending governance actions.

---

## 4. Verification & Testing Evidence

The security invariants are programmatically validated across 18 automated tests in `ai-engine/tests/test_identity.py` and 5 frontend unit tests in `frontend/src/auth/AuthProvider.test.jsx`:

| Test Case | Invariant Tested | Status |
|---|---|---|
| `test_valid_oidc_token_extracts_identity` | RSA RS256 signature verification and claim mapping | PASSED |
| `test_token_with_invalid_issuer_rejected` | Rejection of untrusted token issuer | PASSED |
| `test_token_with_invalid_audience_rejected` | Rejection of token destined for other applications | PASSED |
| `test_expired_token_rejected` | Expired OIDC credentials strictly rejected | PASSED |
| `test_wallet_challenge_issuance_and_siwe` | EIP-4361 SIWE challenge generation and EIP-191 verification | PASSED |
| `test_challenge_replay_attack_rejected` | Single-use nonce enforcement | PASSED |
| `test_cross_tenant_wallet_binding_attempt_rejected` | Cross-tenant binding attempt fails with Tenant mismatch | PASSED |
| `test_wallet_rotation_increments_authorization_generation` | Rotation increments generation (1 -> 2) | PASSED |
| `test_api_identity_me_unauthorized_when_oidc_enabled` | Missing/invalid credentials return HTTP 401 | PASSED |
| `test_api_challenge_strict_validation` | Pydantic V2 extra="forbid" rejects unexpected request fields | PASSED |
| `AuthProvider.test.jsx` (5 tests) | React state, token persistence, SIWE signing, error propagation | PASSED |
