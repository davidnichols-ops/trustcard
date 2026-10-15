# Enterprise deployment boundary

The delivered operations surface is a local release candidate. The read-only console, scoped token primitives, publisher verifier and signed call receipts are building blocks. Fleet SSO, managed approval, remote policy distribution, central key custody and SIEM integrations are future integrations, not implemented product claims.

## Integration map

1. **Device inventory:** managed client configuration declares server, transport, stable gate runtime and policy location. Record direct routes and bypass/audit modes explicitly. Inventory is not enforcement: direct access to an upstream must be constrained separately if the organization requires a mandatory boundary.
2. **Identity:** use the organization's IdP and a dedicated MCP resource audience. Map verified groups to narrow scopes. Use an existing supported introspector only after audience, issuer, expiry, revocation and tenant-binding behavior have been tested; the local development issuer does not provide enterprise SSO.
3. **Policy:** a control plane stores versioned desired policy; authorized reviewers sign changes. Device agents verify signer trust, version monotonicity, expiry and targeting before atomic activation. Existing fleet renewal must not become a remote unsigned policy updater. Denials and approvals need distinct authority and immutable audit events.
4. **Key custody:** separate publisher identity, operator policy signing and runtime receipt signing. Use device-bound OS key storage or enterprise KMS with explicit export/rotation policy; current file keys are not a Keychain/KMS integration. Preserve compromised-key history and follow an approved rotation instead of reusing exposed identity.
5. **Monitoring:** export call receipts and denial events through an authenticated collector. Verify content, signatures, expected signer and ordering before indexing. Add startup/config-load events, stream identity and externally anchored checkpoints: a locally valid chain alone does not detect truncation of its tail or deletion of the entire file. Current HTTP receipts cover successful calls, not a complete decision feed.
6. **Console:** evolve the local view into client × principal × tool coverage, a reviewed policy diff, and an event stream. RBAC must bind every read/write to a verified tenant/principal. Every apply operation must show impact and deployment state. Do not expose the local unauthenticated console as a fleet web service.
7. **Rollout:** distribute a pinned package through device management, verify artifact digest and executable availability, stage on a canary device, retain the previous runtime and test recovery from upstream outage, expired policy, key rotation, dropped audit writes and concurrent edits. Add remote gateways and enterprise claims only after those paths have runtime evidence.

## Release acceptance

Local unit tests and a Mac deployment demonstrate only those environments. Require a clean Linux/Windows/macOS matrix, independent security review of HTTP streaming/session handling, OAuth conformance, multiwriter receipt behavior, package provenance and rollback tests before making general enterprise production claims. The existing proxies still include explicit audit bypass and auto-update modes; enterprise policy must prohibit these when mandatory enforcement is required.
