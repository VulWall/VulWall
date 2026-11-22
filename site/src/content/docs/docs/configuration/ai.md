---
title: AI recommendations
description: Optional AI remediation guidance and executive summaries with an AI provider API key.
---

VulWall works without AI. Every finding shows the scanner's own description and, when the scanner
provides them, remediation advice and references.

With an API key for an AI provider (Anthropic for now), VulWall also:

- writes business and technical remediation guidance for each **finding type** (for example
  "missing HSTS header"), once, and shows it with every finding of that type;
- writes an executive summary for each finished scan, shown in the summary report.

## Turn it on

Add your key to `.env` and apply it:

```sh
AI_API_KEY=sk-ant-...
```

```sh
docker compose up -d
```

The scanner starts its knowledge-base engine only when the key is set. Finding types that were
found before you set the key are queued and processed once it is set. Scans that finished less
than 7 days before you set the key get an executive summary too.

| Variable | Default | Purpose |
|----------|---------|---------|
| `AI_API_KEY` | empty | The provider's API key. Empty turns AI off. |
| `AI_PROVIDER` | `anthropic` | The AI provider. Only `anthropic` is supported for now. |
| `AI_MODEL` | `claude-sonnet-5-5` | Model for the guidance and the executive summaries. |
| `AI_BASE_URL` | the provider's API | Base URL of a gateway or proxy in front of the provider's API. Must be https; http only to a local host (loopback, private IP, `localhost`, a `.local`/`.internal` name or a single-label name such as a compose service). Any other value turns AI off with an error in the log. The scanner sends the key in the `x-api-key` header, the web app as `Authorization: Bearer`. |

The guidance uses Anthropic's web search tool to look up advisories and references. AI output is
checked before it is stored: an answer that is incomplete, too short or in the wrong format is
dropped, and the finding keeps the scanner's own text (or the report has no executive summary).

## What is sent to Anthropic

- For guidance, once per finding type: the type, title, severity, description and source scanner
  of one example finding, and some of its metadata. The scanner leaves out metadata that comes
  from the scanned system, so a target cannot inject instructions into the prompt.
- For an executive summary: the number of findings per severity, and the title, impact and
  explanation of up to three Critical or High findings.

Nothing is sent when `AI_API_KEY` is empty. API usage is billed to your Anthropic account.
