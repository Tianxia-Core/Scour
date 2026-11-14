<p align="center">
  <img src="./brand-kit/01-logos/lockups-and-social/dual-lockup-rxm-x-tianxiaos.svg" alt="RASA-X-MACHINA · tianxiaOS" width="740"/>
</p>

# Scour

[![Architecture Tier](https://img.shields.io/badge/Architecture-Tier_3_Autonomous_Organism-a855f7)](https://github.com/Tianxia-Core)
[![tianxiaOS Substrate](https://img.shields.io/badge/Substrate-tianxiaOS_v8.7.0-7c5cff)](https://github.com/Tianxia-Core/tianxiaos-releases)
[![Nix Flake Closure](https://img.shields.io/badge/Nix_Flake-inputs.nixpkgs.follows-22d3ee)](#normalized-nix-flake-integration-zero-store-duplication)
[![DSS-14.2 Gate](https://img.shields.io/badge/DSS--14.2-%E2%89%A48_FFPs_Verified-34d399)](#function-feature-pair-ffp-manifest)

> **RASA-X-MACHINA Sovereign Polyglot Systems · Makers of `tianxiaOS`**
> *Entity Candor: **RASA-X-MACHINA** — Dealum Application `#179423` under active Estonian Startup Committee evaluation (§ 100¹ of the Estonian Aliens Act · Proposed entity upon approval: **RASA-X-MACHINA OÜ**, Tallinn, Estonia)*
> **Live Surface:** [radar.rasaxmachina.com](https://radar.rasaxmachina.com) · **Press & Brand Kit:** [rasaxmachina.com/press](https://rasaxmachina.com/press) · **Founder:** [rasaxmachina.com/collins](https://rasaxmachina.com/collins) · **Secure WhatsApp Relay:** [rasaxmachina.com/whatsapp](https://rasaxmachina.com/whatsapp)

**`Scour`** unifies the **Pillar 4 Market-Intelligence Harvester (`tx_scour` + `Tyrawn` revgen feed)** and the **Autonomous Opportunity & Capital-Allocation Miner (`tx_opportunities_miner`)** into a clean, wire-coupled **Tier-3 Organism** (`6` FFPs `<= 8` FFPs). It ingests real-time signals across GitHub, arXiv, DeFiLlama, CISA KEV / NVD / ThreatFox, RemoteOK, TechCrunch funding rounds (`Tyrawn`), and x402 endpoints, scoring each opportunity under the Daśavidyāyāna Priority Calculus (`Rank = P + C + A + E + F`) at `$0.00` marginal infrastructure cost (`MIF+50`).

---

## Frontline-to-Founder Engineering Lineage

Architected by **Collins Takem** — forged from **10+ years on the FinTech incident-triage and ledger-forensics front lines** (*Blockchain.com*, *CoinLedger*, *SQUIRE*) while completing a Dual Major in **Pure Mathematics & Computer Science at SUNY (`4.00 / 4.00` GPA)**, followed by **3+ years** building **`tianxiaOS`** and its self-hosted autonomous compiler harnesses.

---

## Function-Feature Pair (`FFP`) Manifest (`<= 8` FFPs Bounded Law)

| FFP ID | Architectural Fitness Class | Language | Source Artifact & Capability |
| :--- | :--- | :--- | :--- |
| `FFP-SCOUR-DISPATCH` | `io-edge` | `Python` | `src/tx_scour.py` — Multi-channel signal dispatcher & URL-deduplicated `MERGED_SIGNALS.jsonl` merger |
| `FFP-SCOUR-EXTRA` | `io-edge` | `Python` | `src/tx_scour_extra.py` — DeFiLlama, HN, GNews, Codeberg, Nature & x402 channel adapters |
| `FFP-TYRAWN-SCOUR` | `io-edge` | `Python` | `src/tx_tyrawn_scour.py` — **Tyrawn** revgen funding-round & RemoteOK expansion signal harvester |
| `FFP-CONV-SCOUR` | `data-science` | `Python` | `src/tx_conv_scour.py` — Conversion & pricing benchmark harvester |
| `FFP-THREAT-INTEL` | `io-edge` | `Python` | `src/tx_threatintel.py` — CISA KEV, NVD, URLhaus & ThreatFox IOC ingestion |
| `FFP-OPPORTUNITY-MINER` | `data-science` | `Python` | `src/tx_opportunities_miner.py` — `Rank = P + C + A + E + F` SFI scorer & B2B sprint strike mapper |

---

## Stratified Wire & Boundary Contract

- **Tier Classification**: **Tier 3 — Autonomous Intelligence & Revenue-Routing Organism** (`radar.rasaxmachina.com` / `alpha.rasaxmachina.com`).
- **Decoupled Wire Contract**: Emits append-only JSONL records conforming to `schemas/merged_signals.schema.json` (`MERGED_SIGNALS.jsonl`) and NATS JetStream `tianxia.core.signals.>`, with `AUTONOMY_PAUSED` / `PROBE_STOP` kill-switch compliance (`BAGALAMUKHI` Loop Discipline).

---

## Normalized Nix Flake Integration (Zero `/nix/store` Duplication)

Per the **RASA-X-MACHINA 3-Tier Stratified Flake Standard**, every Tier-2 Enclave and Tier-3 Organism normalizes `nixpkgs` and `tianxia-core` via `inputs.<x>.follows` so microVM closures compile against a single deterministic `/nix/store` hash:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    tianxia-core = {
      url = "github:Tianxia-Core/TianxiaOS";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
}
```

---

## Quickstart & Verification

```bash
python3 src/tx_scour.py --help
TX_BASE_DIR=/tmp/tx_demo python3 src/tx_tyrawn_scour.py techstack --dry
python3 security/secret_shield.py
```

---

## Security, Press & Governance (Bot-Shielded)

- **RFC 9116 Vulnerability Disclosure**: [`SECURITY.md`](./SECURITY.md) · [trust.rasaxmachina.com](https://trust.rasaxmachina.com)
- **Official Media, PR & Canonical Logos**: [rasaxmachina.com/press](https://rasaxmachina.com/press)
- **Encrypted Founder Dispatch**: [rasaxmachina.com/collins#encrypted-dispatch](https://rasaxmachina.com/collins#encrypted-dispatch) · [rasaxmachina.com/whatsapp](https://rasaxmachina.com/whatsapp)
