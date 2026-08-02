// Tests for the Annex IV PDF renderer (markdownToHtml + buildPrintDocument).
//
// The renderer only has to cover the markdown subset our own templates
// emit (lib/annexIV.js + backend pkg/compliance), so the contract is:
//   1. All report content is HTML-escaped (scanned repos control dep
//      names — a malicious package name must never become live markup).
//   2. Headings, bullets (nested), checkboxes, tables, bold/italic/code
//      all render.
//   3. Underscores inside code spans never trigger italics.
//   4. The print document carries the provenance footer (ledger hash).
import { describe, it, expect } from 'vitest';

import { markdownToHtml, buildPrintDocument } from './annexIVPdf.js';

describe('markdownToHtml', () => {
  it('escapes HTML in content (dep names are attacker-controlled)', () => {
    const html = markdownToHtml('- **<script>alert(1)</script>** (v1.0)');
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('renders heading levels 1-3', () => {
    const html = markdownToHtml('# Title\n## Section\n### Sub');
    expect(html).toContain('<h1>Title</h1>');
    expect(html).toContain('<h2>Section</h2>');
    expect(html).toContain('<h3>Sub</h3>');
  });

  it('renders bold, italic, and code spans', () => {
    const html = markdownToHtml('**Resource:** `p4d.24xlarge` _(source: terraform)_');
    expect(html).toContain('<strong>Resource:</strong>');
    expect(html).toContain('<code>p4d.24xlarge</code>');
    expect(html).toContain('<em>(source: terraform)</em>');
  });

  it('does not italicise snake_case inside code spans', () => {
    const html = markdownToHtml('See `pytorch_model_weights_v2.bin` for details');
    expect(html).toContain('<code>pytorch_model_weights_v2.bin</code>');
    expect(html).not.toContain('<em>');
  });

  it('renders checkbox list items with distinct done/todo markers', () => {
    const html = markdownToHtml('- [x] High-risk constraints validated.\n- [ ] Manual input required.');
    expect(html).toContain('class="check done"');
    expect(html).toContain('class="check todo"');
    expect(html).toContain('High-risk constraints validated.');
  });

  it('renders nested bullets as nested lists', () => {
    const html = markdownToHtml('- **Resource:** gpu-node\n  - **Finding:** unoptimized');
    // Two opens for the nested structure, both closed.
    expect(html.match(/<ul>/g)).toHaveLength(2);
    expect(html.match(/<\/ul>/g)).toHaveLength(2);
    expect(html).toContain('<li><strong>Finding:</strong> unoptimized</li>');
  });

  it('renders the risk-register table with header and body rows', () => {
    const md = [
      '| Component | Severity |',
      '|---|---|',
      '| `torch` | High |',
      '| `langchain` | Critical |',
    ].join('\n');
    const html = markdownToHtml(md);
    expect(html).toContain('<th>Component</th>');
    expect(html).toContain('<td><code>torch</code></td>');
    expect(html).toContain('<td>Critical</td>');
    // Separator row must not leak into the body.
    expect(html).not.toContain('---');
  });

  it('keeps plain digits in prose intact (sentinel round-trip)', () => {
    const html = markdownToHtml('Scanned 5 files across 3 layers');
    expect(html).toContain('Scanned 5 files across 3 layers');
  });

  it('renders bold spanning a hard-wrapped paragraph line', () => {
    const html = markdownToHtml('For scan payloads, **you are the\ncontroller** under GDPR.');
    expect(html).toContain('<strong>you are the controller</strong>');
    expect(html).not.toContain('**');
  });

  it('renders fenced code blocks with escaped, format-free content', () => {
    const html = markdownToHtml('```yaml\nuses: aicaplabs/AIcap@v1.2.0\nkey: **not bold** <tag>\n```');
    expect(html).toContain('<pre><code>uses: aicaplabs/AIcap@v1.2.0');
    expect(html).toContain('**not bold** &lt;tag&gt;');
    expect(html).not.toContain('<strong>');
  });

  it('folds indented continuation lines into the previous list item', () => {
    const html = markdownToHtml('- Account data: deleted\n  within 30 days.\n- Logs: 30 days.');
    expect(html).toContain('<li>Account data: deleted within 30 days.</li>');
    expect(html.match(/<li>/g)).toHaveLength(2);
    expect(html).not.toContain('<p>');
  });

  it('renders bold spanning a wrapped list-item line', () => {
    const html = markdownToHtml('- PURLs matter; **weight files have\n  no CVE identifiers**, so beware.');
    expect(html).toContain('<strong>weight files have no CVE identifiers</strong>');
    expect(html).not.toContain('**');
  });
});

describe('buildPrintDocument', () => {
  it('embeds the ledger hash in the provenance footer and title', () => {
    const doc = buildPrintDocument('# Report', { hash: 'abcdef1234567890' });
    expect(doc).toContain('<title>annex-iv-abcdef12</title>');
    expect(doc).toContain('Immutable ledger entry');
    expect(doc).toContain('abcdef1234567890');
    // "Exported", not "Generated" — see the footer-wording tests below.
    expect(doc).toContain('Exported');
  });

  it('falls back to a slugged project name when there is no hash', () => {
    const doc = buildPrintDocument('# Report', { projectName: 'My Project!' });
    expect(doc).toContain('<title>annex-iv-my-project-</title>');
    expect(doc).not.toContain('Immutable ledger entry');
  });
});

// Blockquotes carry every legally protective statement the product
// makes: the Article 5 "not a finding of breach" disclaimer, the
// Article 50 framing that these are disclosure duties, and the § 5
// unattested-provenance warning. Before this branch existed they were
// HTML-escaped to "&gt;" and run together into a single paragraph, so a
// generated PDF delivered those disclaimers as garbled prose in the one
// document where they matter most.
describe('markdownToHtml blockquotes', () => {
  const NL = String.fromCharCode(10);

  it('renders a multi-line blockquote as one quoted paragraph', () => {
    const html = markdownToHtml(
      ['> **Warning.**', '> Second line of the same thought.', '', 'After.'].join(NL),
    );
    expect(html).toContain('<blockquote>');
    expect(html).toContain('<strong>Warning.</strong> Second line of the same thought.');
    expect(html).not.toContain('&gt;');
    expect(html).toContain('<p>After.</p>');
  });

  it('splits paragraphs inside a quote on a bare marker', () => {
    const html = markdownToHtml(['> First para.', '>', '> Second para.'].join(NL));
    expect((html.match(/<p>/g) || []).length).toBe(2);
  });

  it('does not swallow the content that follows', () => {
    const html = markdownToHtml(['> quoted', '- list item'].join(NL));
    expect(html).toContain('<blockquote>');
    expect(html).toContain('<li>list item</li>');
  });

  it('still escapes HTML inside a quote', () => {
    const html = markdownToHtml('> <script>alert(1)</script>');
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });
});

// Emphasis that ends in a code span.
//
// § 2(a) renders its location suffix as `_found at \`file.go:12\`_`, and
// that shape did not render: the code-span placeholder inserted before
// the italic pass contained underscores, so the italic body ([^_]+)
// could never span it. Every one of ~47 location suffixes in a real
// report reached the reader with literal underscores around it.
describe('markdownToHtml emphasis around code spans', () => {
  it('italicises a run that ends in a code span', () => {
    const html = markdownToHtml('- **x** (v1.0): d — _found at `a.go:1`_');
    expect(html).toContain('<em>found at <code>a.go:1</code></em>');
    expect(html).not.toContain('_found at');
  });

  it('italicises a run containing several code spans', () => {
    const html = markdownToHtml('- **x**: d — _3 occurrences, at `a.go`, `b.go`_');
    expect(html).toContain('<em>3 occurrences, at <code>a.go</code>, <code>b.go</code></em>');
  });

  it('still leaves snake_case identifiers alone', () => {
    expect(markdownToHtml('snake_case_identifier stays literal'))
      .toContain('snake_case_identifier');
    expect(markdownToHtml('snake_case_identifier stays literal'))
      .not.toContain('<em>');
  });

  it('still renders underscores inside a code span verbatim', () => {
    const html = markdownToHtml('code with `under_score` inside');
    expect(html).toContain('<code>under_score</code>');
    expect(html).not.toContain('<em>');
  });
});

// The footer date is an export timestamp, not a generation timestamp.
//
// The document body already carries its own "*Generated:*" line and, in
// § 5, the scan timestamp — both from the scan. Labelling the footer
// "Generated" too put two different dates under the same word in an
// audit document, leaving a reader to guess which one was authoritative.
describe('buildPrintDocument footer wording', () => {
  it('labels the footer timestamp as an export, not a generation', () => {
    const html = buildPrintDocument('# Doc', { hash: 'abc123def456' });
    expect(html).toContain('Exported ');
    expect(html).not.toMatch(/Generated \d{4}-\d{2}-\d{2}/);
  });

  it('still carries the ledger hash for traceability', () => {
    const html = buildPrintDocument('# Doc', { hash: 'abc123def456' });
    expect(html).toContain('Immutable ledger entry:');
    expect(html).toContain('abc123def456');
  });

  it('does not disturb a "Generated:" line inside the document body', () => {
    // The body's own generation stamp is a different fact and must survive.
    const html = buildPrintDocument('*Generated: 2026-08-01T10:14:32Z*', {});
    expect(html).toContain('2026-08-01T10:14:32Z');
    expect(html).toContain('Exported ');
  });
});
