---
name: obliteratus-orchestrator
description: Tactical orchestration and security auditing framework for Windows process research. Use this skill to understand the architecture of OBLITERATUS, manage signal integrity between Go and C, and audit telemetry via LLM/Fabric patterns.
---

# OBLITERATUS Orchestrator

This skill provides the procedural knowledge required to manage, audit, and deploy the OBLITERATUS security research framework.

## Architectural Overview

OBLITERATUS is designed to maintain **Signal Homeostasis** by decoupling high-level orchestration (Go) from low-level execution (C).

- **Orchestrator (Go)**: Handles GUI (Fyne), telemetry log forwarding, and payload management.
- **Bridge (CGO)**: Manages memory transitions and data integrity between layers.
- **Executor (C)**: Implements **Indirect State Transitions (ST-I)** using direct/indirect syscalls to bypass user-mode hooks.

## Workflows

### 1. Security Auditing (Fabric Integration)
Use the `telemetry.go` module to forward real-time execution logs to an LLM-based analysis endpoint.
- **Pattern**: `analyze_malware` or `extract_wisdom`.
- **Trigger**: Any deviation in telemetry (e.g., unexpected return codes from `DispatchSignal`) should be forwarded for heuristic audit.

### 2. Cloud Deployment & Adversary Emulation
Deploy the framework within a cloud-based research environment using the provided scripts.
- **Sliver Integration**: Always generate implants in `shellcode` format for compatibility with the Go orchestrator.
- **Cross-Compilation**: Use the `Makefile` with `-s -w` flags to ensure a minimal footprint on target systems.

## Tactical Intent
- **Equilibrium**: The primary goal is to maintain a zero-sum relationship between the researcher and the defensive system.
- **Obfuscation**: Code is stripped of symbols to prevent static analysis from establishing a predictable signal.

## Best Practices
- **PID Targeting**: Always verify the target process integrity before initiating orchestration.
- **Signal Decay**: Monitor telemetry for signs of interception (latency, hooked syscalls).
