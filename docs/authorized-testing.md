# Authorized testing and disclosure

Created by [@kvianAR](https://github.com/kvianAR).

## Scope record

Before connecting an external target, record the owner, repository/deployment identifier, authorized local or staging instance, permitted hosts/ports, test accounts, synthetic resources, allowed tools/destinations, request limits, dates, and cleanup expectations. Keep credentials in local environment variables.

Running the bundled owned loopback demo uses public synthetic fixtures. Public source availability does not authorize attacks against someone else's hosted deployment. An existing authorization covers the agreed actions and does not need repeated confirmation.

## Applicability before selection

Check adapter request/response mapping, session behavior, trusted fixture policy, expected principal identity, trace provenance, permitted effects, and visibility into the resource boundary. Missing capabilities must remain unsupported/unverified. Record why a proposed target is applicable or deferred before drawing security conclusions.

## Minimal evidence

Use synthetic data and mock sinks where possible. Establish the smallest necessary forbidden result. Avoid real customer data and unrelated resources. Keep artifacts private and redact before storage. Follow the agreed cleanup procedure.

## Disclosure

Validate the evidence and affected scope, prepare a minimal reproduction, and ask the project owner/user to approve external disclosure. Use the maintainer's security process, coordinate remediation, and publish only agreed redacted details. Finding real issues is not a release requirement. A no-finding result covers tested scenarios and conditions only.

## Current external validation

No external app or hosted target has been selected or scanned for this implementation. Owned deterministic lab validation is recorded separately. Third-party efficacy and independent held-out results remain unverified.
