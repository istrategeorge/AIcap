// Annex IV client-side renderer tests.
//
// This file is a hand-maintained mirror of the Go renderer in
// pkg/compliance/compliance.go, and AnnexIVPreview builds the document
// from it without ever calling the backend. That means a change to the
// Go template which is not mirrored here simply never reaches the
// dashboard — which is exactly how the FinOps split shipped to the CLI
// and the ledger while the dashboard kept rendering the old section
// with full pricing. These tests pin the parity that has to hold.
import { describe, it, expect } from 'vitest';

import { buildAnnexIVMarkdown } from './annexIV.js';

const scan = {
  projectName: 'demo',
  commitSha: 'abc1234',
  dependencies: [],
  complianceStatus: 'Passed',
  finOps: [{
    resource: 'gpu_instances.tf',
    description: 'AWS instance detected in Terraform config.',
    severity: 'Warning',
    estimatedCost: {
      cloud: 'AWS', instanceFamily: 'p4d.',
      hourlyUsdLow: 32.77, hourlyUsdHigh: 32.77,
      monthlyUsdLow: 23922, monthlyUsdHigh: 23922,
      spotMultiplier: 0.3, spotMonthlyUsdLow: 7177, spotMonthlyUsdHigh: 7177,
    },
  }],
  finOpsCostEstimate: {
    costedFindings: 1, uncostedFindings: 0,
    totalMonthlyUsdLow: 23922, totalMonthlyUsdHigh: 23922,
    currency: 'USD', assumedHoursPerMonth: 730, disclaimer: 'list pricing',
  },
};

describe('buildAnnexIVMarkdown § 2(c)', () => {
  it('describes the compute without pricing it by default', () => {
    const md = buildAnnexIVMarkdown(scan, null);

    expect(md).toContain('### 2(c) Compute & Hardware Resources');
    // The hardware description is an Annex IV Section 2 requirement.
    expect(md).toContain('gpu_instances.tf');
    expect(md).toContain('Instance family:');
    expect(md).toContain('p4d.');

    // The money is not, and must not appear in the auditor-facing doc.
    expect(md).not.toContain('Estimated cost:');
    expect(md).not.toContain('23922');
    expect(md).not.toContain('Estimated total monthly cost:');
    expect(md).not.toContain('Spot/preemptible projection:');
    expect(md).not.toMatch(/FinOps Telemetry/);
  });

  it('includes cost figures when explicitly requested', () => {
    const md = buildAnnexIVMarkdown(scan, null, { includeCosts: true });

    expect(md).toContain('### 2(c) Compute & Hardware Resources (with cost estimates)');
    expect(md).toContain('Estimated cost:');
    expect(md).toContain('23922');
    expect(md).toContain('Estimated total monthly cost:');
  });

  it('returns the backend markdown verbatim for a historical proof', () => {
    // Historical proofs are rendered server-side and stored; the client
    // must not re-render them, or a stored document would change shape
    // after the fact.
    const md = buildAnnexIVMarkdown(scan, { markdown: '# stored document' });
    expect(md).toBe('# stored document');
  });

  it('handles a scan with no FinOps findings', () => {
    const md = buildAnnexIVMarkdown({ ...scan, finOps: [], finOpsCostEstimate: null }, null);
    expect(md).toContain('No specific hardware constraints');
  });
});

// § 2(a) parity with the Go renderer (pkg/compliance/compliance.go).
//
// This mirror has silently diverged from the backend three times now —
// the FinOps split, the "v" prefix, and the § 2(a) grouping all shipped
// to the CLI and the ledger while the dashboard kept rendering the old
// form. These assertions encode the shape the Go renderer produces, so a
// future change made on one side and not the other fails here.
describe('buildAnnexIVMarkdown § 2(a) parity', () => {
  const base = {
    projectName: 'demo', commitSha: 'abc', complianceStatus: 'Passed',
    finOps: [], finOpsCostEstimate: null,
  };

  it('prefixes "v" only on real versions', () => {
    const md = buildAnnexIVMarkdown({
      ...base,
      dependencies: [
        { name: 'openai', version: '1.12.0', ecosystem: 'Python (pip)', riskLevel: 'High', description: 'x' },
        { name: 'Hardcoded Model', version: 'gpt-5', ecosystem: 'Source Code (.go)', riskLevel: 'High', description: 'y' },
        { name: 'torch', version: '>=2.0', ecosystem: 'Python (pip)', riskLevel: 'High', description: 'z' },
        { name: 'transformers', version: 'imported', ecosystem: 'Python (pip)', riskLevel: 'High', description: 'w' },
      ],
    }, null);

    expect(md).toContain('(v1.12.0)');
    expect(md).toContain('(gpt-5)');
    expect(md).toContain('(>=2.0)');
    expect(md).toContain('(imported)');
    // The bug the dashboard shipped with.
    expect(md).not.toContain('(vgpt-5)');
    expect(md).not.toContain('(v>=2.0)');
    expect(md).not.toContain('(vimported)');
  });

  it('collapses repeated detections and names where they were found', () => {
    const md = buildAnnexIVMarkdown({
      ...base,
      dependencies: [
        { name: 'Hardcoded Model', version: 'gpt-5', ecosystem: 'Source Code (.go)', riskLevel: 'High', description: 'y', location: 'a.go:1' },
        { name: 'Hardcoded Model', version: 'gpt-5', ecosystem: 'Source Code (.go)', riskLevel: 'High', description: 'y', location: 'b.go:2' },
        { name: 'Hardcoded Model', version: 'gpt-5', ecosystem: 'Source Code (.go)', riskLevel: 'High', description: 'y', location: 'a.go:1' },
      ],
    }, null);

    // One line, not three.
    expect((md.match(/\*\*Hardcoded Model\*\*/g) || []).length).toBe(1);
    // Duplicate locations collapse: two distinct sites, not three.
    expect(md).toContain('2 occurrences');
    expect(md).toContain('a.go:1');
    expect(md).toContain('b.go:2');
  });

  it('says "found at" for a single occurrence', () => {
    const md = buildAnnexIVMarkdown({
      ...base,
      dependencies: [
        { name: 'openai', version: '1.0.0', ecosystem: 'Python (pip)', riskLevel: 'High', description: 'x', location: 'req.txt' },
      ],
    }, null);
    expect(md).toContain('found at');
    expect(md).not.toContain('occurrences');
  });
});
