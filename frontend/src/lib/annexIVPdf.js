// Annex IV PDF export — renders the report markdown into a styled,
// print-ready HTML document and hands it to the browser's print engine
// ("Save as PDF"). Zero new dependencies: the markdown is produced by
// our own templates (lib/annexIV.js locally, pkg/compliance on the
// backend), so the renderer only has to cover that known subset:
// #/##/### headings, - bullets (2-space nesting), - [x] checkboxes,
// | tables |, **bold**, _italic_, `code`, and --- rules.
//
// Auditors and notified bodies exchange PDFs, not markdown — this is
// the artifact a compliance officer can actually forward.

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Inline formatting. Code spans are lifted out first so underscores and
// asterisks inside `snake_case_paths` never trigger em/strong rules.
function renderInline(text) {
  const codeSpans = [];
  let s = escapeHtml(text);
  s = s.replace(/`([^`]+)`/g, (_, code) => {
    codeSpans.push(code);
    // The placeholder must contain no underscore. The italic rule
    // matches a body of [^_]+, so a token like @@AICAP_CODE_0@@ could
    // never sit inside emphasis — which is exactly the shape § 2(a)
    // produces (`_found at \`file.go:12\`_`), and why every location
    // suffix rendered with literal underscores around it.
    return `@@AICAPCODE${codeSpans.length - 1}@@`;
  });
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  // Italics. The boundary classes deliberately include the code-span
  // placeholder delimiter (@) and the backtick, because emphasis in this
  // document routinely wraps a run that ends in a code span — the § 2(a)
  // location suffix is `_found at \`file.go:12\`_`. Without that, the
  // closing underscore sat against a placeholder rather than whitespace,
  // the rule did not fire, and every one of those suffixes reached the
  // reader as literal underscores.
  //
  // The `[^_]+` body still prevents a match from spanning snake_case
  // identifiers, which is what the boundary was guarding against.
  s = s.replace(/(^|[\s(`@])_([^_]+)_(?=$|[\s).,;:`@])/g, '$1<em>$2</em>');
  s = s.replace(/@@AICAPCODE(\d+)@@/g, (_, i) => `<code>${codeSpans[i]}</code>`);
  return s;
}

function isTableSeparator(line) {
  const cells = line.replace(/^\|/, '').replace(/\|$/, '').split('|');
  return cells.length > 0 && cells.every(c => /^\s*:?-{2,}:?\s*$/.test(c) || /^\s*-+\s*$/.test(c));
}

function splitRow(line) {
  return line.replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim());
}

export function markdownToHtml(markdown) {
  const lines = markdown.split(/\r?\n/);
  const out = [];
  let listDepth = 0; // number of currently open <ul>
  let para = [];
  // Raw source of the most recently emitted <li>, so wrapped
  // continuation lines can be folded in and the item re-rendered as a
  // whole — inline formatting may span the wrap.
  let lastLi = null; // { marker, raw }

  const flushPara = () => {
    if (para.length > 0) {
      // Join wrapped source lines BEFORE inline rendering so **bold**
      // and _italics_ spanning a hard line break still match.
      out.push(`<p>${renderInline(para.join(' '))}</p>`);
      para = [];
    }
  };
  const closeListsTo = (depth) => {
    while (listDepth > depth) {
      out.push('</ul>');
      listDepth--;
    }
  };

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    // Blank line: paragraph/list boundary.
    if (/^\s*$/.test(line)) {
      flushPara();
      closeListsTo(0);
      i++;
      continue;
    }

    // Fenced code blocks (``` ... ```). Content is escaped verbatim —
    // no inline formatting applies inside a fence.
    if (/^```/.test(line.trim())) {
      flushPara();
      closeListsTo(0);
      const code = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i].trim())) {
        code.push(lines[i]);
        i++;
      }
      i++; // consume closing fence (or EOF)
      out.push(`<pre><code>${escapeHtml(code.join('\n'))}</code></pre>`);
      continue;
    }

    // Headings.
    const heading = line.match(/^(#{1,3}) (.*)$/);
    if (heading) {
      flushPara();
      closeListsTo(0);
      const level = heading[1].length;
      out.push(`<h${level}>${renderInline(heading[2])}</h${level}>`);
      i++;
      continue;
    }

    // Horizontal rule.
    if (/^---+\s*$/.test(line)) {
      flushPara();
      closeListsTo(0);
      out.push('<hr>');
      i++;
      continue;
    }

    // Blockquotes: consecutive lines starting with '>'.
    //
    // Not a cosmetic omission. Every legally protective statement this
    // product makes is a blockquote — the Article 5 "this is not a
    // finding that you are committing a prohibited practice" disclaimer,
    // the Article 50 framing that these are disclosure duties rather
    // than prohibitions, and the § 5 warning that a locally generated
    // document is unattested and cannot be independently verified.
    // Without this branch those lines were HTML-escaped to "&gt;" and
    // run together into one paragraph, so the disclaimers reached the
    // reader as garbled prose in exactly the document where they matter
    // most.
    if (/^\s*>/.test(line)) {
      flushPara();
      closeListsTo(0);
      const quoted = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) {
        // Strip the marker and one optional following space. A bare '>'
        // is a paragraph break inside the quote.
        quoted.push(lines[i].replace(/^\s*>\s?/, ''));
        i++;
      }
      const paras = [];
      let buf = [];
      for (const q of quoted) {
        if (q.trim() === '') {
          if (buf.length) paras.push(buf.join(' '));
          buf = [];
        } else {
          buf.push(q);
        }
      }
      if (buf.length) paras.push(buf.join(' '));
      out.push(
        `<blockquote>${paras.map(p => `<p>${renderInline(p)}</p>`).join('')}</blockquote>`,
      );
      continue;
    }

    // Tables: consecutive lines starting with '|'.
    if (line.trimStart().startsWith('|')) {
      flushPara();
      closeListsTo(0);
      const rows = [];
      while (i < lines.length && lines[i].trimStart().startsWith('|')) {
        rows.push(lines[i].trim());
        i++;
      }
      const hasHeader = rows.length >= 2 && isTableSeparator(rows[1]);
      let html = '<table>';
      if (hasHeader) {
        html += `<thead><tr>${splitRow(rows[0]).map(c => `<th>${renderInline(c)}</th>`).join('')}</tr></thead>`;
      }
      const bodyRows = hasHeader ? rows.slice(2) : rows;
      html += `<tbody>${bodyRows
        .map(r => `<tr>${splitRow(r).map(c => `<td>${renderInline(c)}</td>`).join('')}</tr>`)
        .join('')}</tbody></table>`;
      out.push(html);
      continue;
    }

    // List items (2-space nesting, checkbox variants).
    const item = line.match(/^(\s*)- (.*)$/);
    if (item) {
      flushPara();
      const depth = Math.min(Math.floor(item[1].length / 2), 3) + 1;
      closeListsTo(depth);
      while (listDepth < depth) {
        out.push('<ul>');
        listDepth++;
      }
      let content = item[2];
      let marker = '';
      if (content.startsWith('[x] ')) {
        marker = '<span class="check done">&#9745;</span> ';
        content = content.slice(4);
      } else if (content.startsWith('[ ] ')) {
        marker = '<span class="check todo">&#9744;</span> ';
        content = content.slice(4);
      }
      lastLi = { marker, raw: content };
      out.push(`<li>${marker}${renderInline(content)}</li>`);
      i++;
      continue;
    }

    // Indented continuation of a wrapped list item: fold it into the
    // previous <li> and re-render the item from its accumulated raw
    // source, so inline formatting spanning the wrap still matches.
    if (
      listDepth > 0 && lastLi && /^\s+/.test(line) &&
      out.length > 0 && out[out.length - 1].endsWith('</li>')
    ) {
      out.pop();
      lastLi.raw += ` ${line.trim()}`;
      out.push(`<li>${lastLi.marker}${renderInline(lastLi.raw)}</li>`);
      i++;
      continue;
    }

    // Plain paragraph line.
    para.push(line.trim());
    i++;
  }

  flushPara();
  closeListsTo(0);
  return out.join('\n');
}

const PRINT_CSS = `
  @page { size: A4; margin: 20mm 18mm; }
  * { box-sizing: border-box; }
  body {
    font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
    color: #1e293b; font-size: 10.5pt; line-height: 1.55; margin: 0;
  }
  h1 { font-size: 17pt; color: #1e1b4b; border-bottom: 2.5pt solid #4f46e5; padding-bottom: 6pt; margin: 0 0 14pt; }
  h2 { font-size: 13pt; color: #312e81; border-bottom: 0.75pt solid #cbd5e1; padding-bottom: 3pt; margin: 18pt 0 8pt; page-break-after: avoid; }
  h3 { font-size: 11pt; color: #334155; margin: 12pt 0 6pt; page-break-after: avoid; }
  p { margin: 6pt 0; }
  ul { margin: 4pt 0; padding-left: 16pt; }
  li { margin: 2.5pt 0; page-break-inside: avoid; }
  code {
    font-family: Consolas, "Courier New", monospace; font-size: 9pt;
    background: #f1f5f9; border: 0.5pt solid #e2e8f0; border-radius: 2pt; padding: 0.5pt 3pt;
  }
  pre { background: #f1f5f9; border: 0.5pt solid #e2e8f0; border-radius: 3pt;
        padding: 6pt 8pt; overflow-x: auto; page-break-inside: avoid; }
  pre code { background: none; border: none; padding: 0; }
  /* Blockquotes carry the document's disclaimers — the Article 5
     "not a finding of breach" warning, the unattested-provenance
     notice. They must read as a callout, not as body text a reader
     skims past. */
  blockquote { margin: 8pt 0; padding: 6pt 10pt; border-left: 2.5pt solid #f59e0b;
               background: #fffbeb; color: #78350f; }
  blockquote p { margin: 3pt 0; }
  table { border-collapse: collapse; width: 100%; font-size: 8.5pt; margin: 8pt 0; page-break-inside: avoid; }
  th, td { border: 0.75pt solid #cbd5e1; padding: 4pt 6pt; text-align: left; vertical-align: top; }
  th { background: #eef2ff; color: #312e81; }
  hr { border: none; border-top: 0.75pt solid #cbd5e1; margin: 12pt 0; }
  .check.done { color: #059669; }
  .check.todo { color: #94a3b8; }
  .doc-footer {
    margin-top: 28pt; padding-top: 8pt; border-top: 0.75pt solid #cbd5e1;
    font-size: 8pt; color: #64748b;
  }
  .doc-footer p { margin: 2pt 0; }
`;

// Full standalone HTML document for the print iframe. The footer block
// carries provenance (ledger hash, generation date) so a printed copy
// remains traceable back to its immutable ledger entry.
export function buildPrintDocument(markdown, { hash, projectName } = {}) {
  const body = markdownToHtml(markdown);
  const title = hash
    ? `annex-iv-${hash.substring(0, 8)}`
    : `annex-iv-${(projectName || 'report').toLowerCase().replace(/[^a-z0-9-]+/g, '-')}`;
  const generated = new Date().toISOString().replace('T', ' ').substring(0, 16) + ' UTC';
  const hashLine = hash
    ? `<p>Immutable ledger entry: <code>${escapeHtml(hash)}</code></p>`
    : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<style>${PRINT_CSS}</style>
</head>
<body>
${body}
<div class="doc-footer">
${hashLine}<p>Generated ${generated} by AIcap — Continuous AI-BOM &amp; EU AI Act Compliance Scanner · https://aicap.dev</p>
</div>
</body>
</html>`;
}

// Open the browser print dialog ("Save as PDF") over a hidden iframe.
// An iframe (vs window.open) survives popup blockers and keeps the
// user on the dashboard. The iframe is removed after printing; the
// 60s fallback covers browsers that never fire afterprint.
export function exportAnnexIVPdf(markdown, meta = {}) {
  const iframe = document.createElement('iframe');
  iframe.style.cssText = 'position:fixed;right:0;bottom:0;width:0;height:0;border:0;';
  iframe.srcdoc = buildPrintDocument(markdown, meta);
  iframe.onload = () => {
    const win = iframe.contentWindow;
    const remove = () => iframe.parentNode && iframe.remove();
    win.onafterprint = remove;
    setTimeout(remove, 60000);
    win.focus();
    win.print();
  };
  document.body.appendChild(iframe);
}
