---
title: AI recommendations
description: Optional AI remediation guidance and executive summaries with an Anthropic API key.
---

VulWall works without AI. Every finding shows the scanner's own description and, when the scanner
provides them, remediation advice and references.

With an Anthropic API key, VulWall also:

- writes business and technical remediation guidance for each **finding type** (for example
  "missing HSTS header"), once, and shows it with every finding of that type;
- writes an executive summary for each finished scan, shown in the summary report.

## Turn it on

Add your key to `.env` and apply it:

```sh
ANTHROPIC_API_KEY=sk-ant-...
```

```sh
docker compose up -d
```

The scanner starts its knowledge-base engine only when the key is set. Finding types that were
found before you set the key are queued and processed once it is set. Scans that finished less
than 7 days before you set the key get an executive summary too.

`ANTHROPIC_MODEL` selects the model for the guidance and the executive summaries (default
`claude-sonnet-4-6`).

## What is sent to Anthropic

- For guidance, once per finding type: the type, title, severity, description and source scanner
  of one example finding, and some of its metadata. The scanner leaves out metadata that comes
  from the scanned system, so a target cannot inject instructions into the prompt.
- For an executive summary: the number of findings per severity, and the title, impact and
  explanation of up to three Critical or High findings.

Nothing is sent when `ANTHROPIC_API_KEY` is empty. API usage is billed to your Anthropic account.
