---
aep: xxx
title: "Private bid market for providers (re-zerve)"
author: Terp Network
status: Draft
type: Standard
created: 2026-09-09
description: "A dedicated side-market so Akash providers can bid privately on Terp without leaving the public Akash marketplace, participating as FROST threshold members."
category: Core
updated: 2026-09-09
---

<!--
Working AEP template. Header order matches AEP-1 (Purpose and Guidelines):
aep, title, author, status, type, created, then optional description / discussions-to / category / updated.
Required body sections from AEP-1: Abstract, Specification, Rationale, Backward Compatibility,
Test Cases (when applicable), Implementations, Security Considerations, Copyright.
Motivation is optional in AEP-1 and included here. Editor assigns the real `aep:` number.
This file is not a submission to akash-network/AEP.
-->

## Abstract

<!-- ~200 words. Technical issue and what this AEP changes. -->

## Motivation

<!-- Why this is needed. Problem for providers, deployers, and the public market. -->

## Specification

<!-- Precise behavior: public ask (deployment/order), bid envelope, commitment, allocate, lease access, close, FROST seats. -->

## Rationale

<!-- Why this design vs public MsgCreateBid-only. -->

## Backward Compatibility

<!-- Public market default when PIR env is unset. Stock provider image unchanged. -->

## Test Cases

<!-- Local e2e sequence. Public allocate still works. Private path fail-closed. -->

## Implementations

<!-- Crate + provider-services lab fork. Available in the local lab. Not on the public network yet. -->

## Security Considerations

<!-- Envelope AEAD, commitment-only public record, bearer derivation, FROST threshold, no vote extensions on escrow. Required by AEP-1. -->

## References

<!-- Akash core concepts, SDL, RFC 8439, RFC 9591, ZIP-32 (named stand-in; ZIP-312 RedPallas is not in Zakura). -->

## Copyright

All content herein is licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0).
