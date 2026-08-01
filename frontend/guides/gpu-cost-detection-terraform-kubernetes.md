---
title: Catching expensive GPU misconfigurations in Terraform and Kubernetes
description: A p4d left on-demand costs six figures a year. How static analysis of your infrastructure manifests surfaces GPU cost risks in CI — before the invoice, and with the numbers your Annex IV file needs anyway.
date: 2026-07-06
---

# Catching expensive GPU misconfigurations in Terraform and Kubernetes

AI infrastructure has a property regular infrastructure doesn't: the unit
prices are violent. An `p4d.24xlarge` on-demand is roughly **$24,000–32,000
a month**. A junior engineer's copy-pasted Terraform block can out-spend an
entire team, and the feedback loop — the cloud invoice — arrives 30+ days
after the merge.

The fix is the same one that works for security: move the check to the
pull request. Your GPU footprint is declared in Terraform, Kubernetes, and
Helm manifests, which means it is statically analysable in CI.

## What a manifest scan can see

- **Terraform**: GPU instance types across AWS (p3/p4d/p4de/p5, g4dn/g5/g6,
  inf1/inf2, trn1), Azure (NC/ND/NV) and GCP (a2/a3, g2), mapped against a
  cost catalog to hourly and monthly ranges
- **Kubernetes**: `nvidia.com/gpu` resource requests without MIG or
  time-slicing configuration — whole physical GPUs allocated where a
  seventh of one would do
- **Helm `values.yaml`**: GPU allocation without autoscaling, plus the
  model-serving frameworks that reveal what the GPUs are for

Each finding arrives with numbers attached, in the PR, where the
conversation is cheap:

```text
Resource: aws_instance.inference_node
Finding:  GPU instance g5.2xlarge without autoscaling policy
Cost:     $1.21–1.45/hr → $880–1,050/month (on-demand)
Spot:     $264–315/month (~30% of on-demand)
```

## The three findings that pay for the setup

**1. Training-class hardware serving inference.** The most expensive
mistake in the catalog: p4d/p5-class instances (built for distributed
training) running steady-state inference that an `inf2` or `g5` serves at
a fraction of the price. Rightsizing detection compares the instance
family against training signals in the repo (DVC pipelines, trainer
imports) — no training signals plus a training-class instance is a flag
worth a human look.

**2. On-demand where spot survives.** Batch scoring, embedding backfills,
and experimentation tolerate interruption; spot pricing runs around 30% of
on-demand across the big three clouds. The scan projects both numbers so
the PR shows the size of the decision, not just its existence.

**3. Whole-GPU requests for fractional workloads.** A K8s pod requesting
`nvidia.com/gpu: 1` for a model that uses 6 GB of an 80 GB A100 wastes
most of a very expensive card. MIG partitioning or time-slicing fixes it;
the scan flags the request that lacks either.

## Why this lives in the compliance file too

The overlap nobody expects: **EU AI Act Annex IV Section 2 asks for the
system's computational resources and hardware requirements.** If you are
documenting a high-risk system anyway, the same manifest scan that guards
your budget fills that section with real figures — instance families,
hourly ranges, monthly projections, and stated assumptions. One CI job,
two audiences: the CFO and the auditor.

That is how the AIcap scanner packages it: FinOps findings render into
Annex IV § 2(c) ("Hardware Requirements & Estimated Monthly Cost") with a
total, a spot projection, and the assumptions block an auditor expects,
while the same numbers show in the dashboard table for engineering review.

## Honest limitations

- Static prices are estimates — catalogs carry low/high ranges, not your
  negotiated rate; the point is *ranking risks*, not replacing billing
  export analysis
- The scan sees declared infrastructure; click-ops GPU instances are
  invisible (also a reason to not have click-ops GPU instances)
- Utilisation-based rightsizing needs runtime metrics; manifest analysis
  gets you the coarse wins (family mismatch, missing spot, missing MIG)
  which are, conveniently, the big ones

## Setup

It is the same scanner, the same job, zero extra flags:

```yaml
- name: AI compliance + FinOps scan
  uses: aicaplabs/AIcap@v1.7.2
  with:
    scan-directory: '.'
```

Terraform, Kubernetes, and Helm files in the tree are analysed
automatically; findings land in the AI-BOM JSON, the PR log, and the Annex
IV draft. The first flagged p4d usually settles the question of whether
the job was worth adding.
