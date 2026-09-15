# BountyBoard — On-chain Bounty Marketplace with Consensus-Verified Work Completion

> **Post bounties, submit proof, get paid — trustlessly.**
> BountyBoard is a decentralized bounty marketplace where anyone can create a
> bounty (task description + reward + deadline) and workers submit proof of
> completion. An LLM evaluates whether the submitted work satisfies the bounty
> requirements, settled by leader/validator consensus — so bounty resolution is
> trustless, not a popularity contest.

[![GenLayer](https://img.shields.io/badge/Built%20on-GenLayer-6366f1?style=for-the-badge&logo=genlayer)](https://genlayer.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Equivalence](https://img.shields.io/badge/Equivalence%20Principle-OK-16a34a?style=for-the-badge)](https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle)
[![Tests](https://img.shields.io/badge/tests-25%20passed-16a34a?style=for-the-badge)]()

---

## Table of Contents

- [Why this is not a thin LLM wrapper](#why-this-is-not-a-thin-llm-wrapper)
- [How it works](#how-it-works)
- [Consensus design](#consensus-design)
- [State design](#state-design)
- [Security & audit](#security--audit)
- [Deployed contract (proof on explorer)](#deployed-contract-proof-on-explorer)
- [Local lint & test](#local-lint--test)
- [Extension ideas](#extension-ideas)

---

## Deployed contract (proof on explorer)

- **Contract address:** `0x8FD53de0764b1238Ef59c417B0369b5207315b52`
- **Explorer:** [explorer-studio.genlayer.com/address/0x8FD53de0764b1238Ef59c417B0369b5207315b52](https://explorer-studio.genlayer.com/address/0x8FD53de0764b1238Ef59c417B0369b5207315b52)

Verified live on studionet: create bounty, fund with GEN (payable), submit work
with nonce-bound signature, claim reward (GEN transfer to worker), cancel with
refund, expire with refund. All views return consistent state. 25 GenVM
direct-mode tests pass, genvm-lint passes.

---

## Why this is not a thin LLM wrapper

The failure mode the contest warns about is a contract that asks an LLM to
decide something and stores the answer. BountyBoard's core value is
**on-chain cryptographic verification and consensus-verified work evaluation**;
the LLM plays only a supporting, consensus-gated role:

| # | Layer | What it guarantees |
|---|---|---|
| 1 | **On-chain ECDSA recovery** | Worker signs `{bounty_id}:{proof_url}` (EIP-191); contract performs **pure-Python secp256k1 ecrecover** and requires recovered signer equals submitting wallet. Cannot be forged from public inputs. |
| 2 | **Provenance binding** | Proof page must embed the worker's signature. Contract fetches and verifies marker presence — no page, no approval. |
| 3 | **AST sandbox ground truth** | LLM translates bounty requirements into boolean expressions; Python AST validates safety; expressions run on-chain against proof content. Programmatic checks cannot be overridden. |
| 4 | **Consensus judge** | LLM evaluates proof against bounty requirements under `run_nondet_unsafe`. Leader proposes verdict, validators reproduce — only if all agree does state change. |
| 5 | **Anti-replay** | Submission sequence number bound into signed message; same signature cannot be reused. |

---

## How it works

```
Poster                     Worker                    Contract (GenLayer)
  │                          │                           │
  │  create_bounty(id,       │                           │
  │    desc, deadline)       │                           │
  │─────────────────────────>│                           │
  │                          │                           │
  │  fund_bounty(id, amt)    │                           │
  │─────────────────────────>│                           │
  │                          │                           │
  │                          │  submit_work(id, url, sig)│
  │                          │──────────────────────────>│
  │                          │                           │
  │                          │  1. Verify sig (ecrecover)│
  │                          │  2. Fetch proof URL       │
  │                          │  3. LLM: generate checks  │
  │                          │  4. AST sandbox eval      │
  │                          │  5. LLM: judge verdict    │
  │                          │  6. Consensus (leader +   │
  │                          │     validators)           │
  │                          │                           │
  │                          │  <-- approved/rejected --│
  │                          │                           │
```

### Bounty lifecycle

1. **Poster** creates a bounty with description, reward, and deadline.
2. **Poster** funds the bounty (increases reward).
3. **Worker** signs `{bounty_id}:{proof_url}` with EIP-191 and submits proof.
4. Contract verifies the worker's signature on-chain (pure-Python secp256k1 ecrecover).
5. Contract fetches the proof URL and, under consensus:
   - LLM translates bounty requirements into boolean expressions (AST sandbox)
   - Expressions evaluated on-chain against proof content
   - LLM judge decides whether work satisfies the bounty
6. If approved, worker receives the reward. If rejected, worker gets nothing and can resubmit (rate-limited).
7. Bounty poster can reject an approved submission (dispute mechanism).
8. After deadline, anyone can expire open/rejected bounties.

---

## Consensus design

```python
def _run_work_consensus(bounty_description, proof_url, signature, worker_addr):
    def leader_fn():
        return _verify_pipeline(bounty_description, proof_url, signature, worker_addr)

    def validator_fn(leader_result):
        my = leader_fn()
        return _decision_fields(my) == _decision_fields(leader_data)

    return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)
```

Each validator independently:
1. Fetches the same proof URL
2. Runs the same LLM check generation
3. Evaluates the same AST expressions
4. Runs the same LLM judge
5. Compares the decision fields (approved: bool) with the leader

Only if leader and all validators agree does the state change.

---

## State design

| Storage | Type | Purpose |
|---------|------|---------|
| `bounties` | `TreeMap[str, Bounty]` | All bounties by ID |
| `submissions` | `TreeMap[str, Submission]` | All submissions by ID |
| `counters` | `TreeMap[str, u256]` | Submission count per worker per bounty |
| `bounty_order` | `DynArray[str]` | Insertion order for enumeration |

### Bounty states

```
open ──────> submitted ──────> approved
  │              │                │
  │              v                v
  │           rejected         rejected
  │              │                │
  v              v                v
expired       expired          expired
```

---

## Security & audit

| Attack vector | Mitigation |
|---------------|------------|
| **Forged signature** | On-chain secp256k1 ecrecover; recovered signer must equal `msg.sender` |
| **Self-approval** | Poster cannot submit work for own bounty |
| **Replay attack** | Sequence number bound into signed message; rate-limited submissions |
| **Prompt injection** | LLM prompts use `UNTRUSTED USER DATA` framing; AST sandbox prevents code execution |
| **SSRF** | Blocked host regex (localhost, private IPs, `.local`, `.internal`) |
| **Overlong input** | Description ≤500 chars, URL ≤2048 chars, content ≤20000 chars |
| **Deadline bypass** | Checked via `datetime.now()` (warp-aware); deadline enforced before consensus |
| **Double-submit** | Rate limit: 1 submission per worker per bounty per cooldown period |
| **AST escape** | Python AST validates all nodes; only string methods and `len` allowed |
| **Signature malleability** | `s > N/2` check rejects duplicate signatures from low-s/high-s pairs |
| **Unauthorized rejection** | `reject_submission` requires `sender == poster` |
| **Resubmission after reject** | Rejected bounties return to open; worker can resubmit with rate limit |
| **SSRF expanded** | Blocklist includes `::1`, `169.254.169.254`, `metadata.*.internal`, `.localhost` |
| **Real custody** | `fund_bounty` accepts GEN via `msg.value`; `claim_reward` transfers via `emit_transfer` |
| **Refund on cancel/expire** | Poster receives GEN refund on cancel or expiry |
| **Nonce-bound signatures** | `{bounty_id}:{proof_url}:{nonce}` prevents signature replay |

---

## Local lint & test

```bash
# Lint
genvm-lint check contracts/bounty_board.py

# Tests (direct mode, ~1.6s)
pytest tests/bounty_board_test.py -v
```

**Test coverage (25 tests):**

| # | Test | What it verifies |
|---|------|------------------|
| 1 | `test_create_and_fund_bounty` | Create + fund lifecycle (payable) |
| 2 | `test_fund_requires_value` | Fund without GEN rejected |
| 3 | `test_cannot_fund_after_submission` | Cannot fund after submission |
| 4 | `test_rejects_bad_bounty_id` | Empty/long bounty_id rejected |
| 5 | `test_rejects_bad_description` | Empty description rejected |
| 6 | `test_rejects_past_deadline` | Past deadline rejected |
| 7 | `test_rejects_duplicate_bounty` | Duplicate bounty_id rejected |
| 8 | `test_rejects_forged_signature` | Wrong wallet signature rejected |
| 9 | `test_rejects_self_submission` | Poster cannot submit own work |
| 10 | `test_submit_and_approve` | Positive path: submit + approve |
| 11 | `test_rejects_no_signature_in_page` | Judge rejects insufficient proof |
| 12 | `test_rejects_after_deadline` | Post-deadline submission rejected |
| 13 | `test_claim_reward` | Claim GEN payout after approval |
| 14 | `test_claim_requires_approved` | Cannot claim unapproved bounty |
| 15 | `test_claim_requires_worker` | Non-worker cannot claim |
| 16 | `test_claim_double_claim` | Double claim rejected |
| 17 | `test_cancel_bounty_refunds` | Cancel refunds poster |
| 18 | `test_cancel_requires_poster` | Non-poster cannot cancel |
| 19 | `test_cancel_only_open` | Cannot cancel after submission |
| 20 | `test_expire_bounty_refunds` | Expire refunds poster |
| 21 | `test_expire_bounty_no_fund` | Expire without funding |
| 22 | `test_nonce_prevents_replay` | Nonce prevents signature replay |
| 23 | `test_reject_submission` | Reject approved submission |
| 24 | `test_views_consistent` | Views return consistent state |
| 25 | `test_get_bounty_submissions` | List submissions per bounty |

---

## Extension ideas

- **Multi-worker competition:** Allow multiple workers to submit; poster picks the best.
- **Milestone bounties:** Partial payments for incremental progress.
- **Reputation system:** Track worker approval rates across bounties.
- **Escrow integration:** Hold funds in a separate escrow contract.
- **Dispute resolution:** Multi-round appeal process with escalating consensus.
