Prioritized vulnerability finding card — the core unit of the NightWatch report. Severity-colored left accent, a severity pill, monospace CVE/host metadata, plain-English title and body, and fix/mute actions.

```jsx
<FindingCard
  level="high"
  cve="CVE-2024-3094"
  host="api.acme.com" port="443"
  title="Outdated OpenSSL exposes the API to a known RCE"
  description="The host advertises OpenSSL 3.0.6, vulnerable to a remote code execution flaw. Upgrade to 3.0.7 or later."
  onFix={() => {}}
  onMute={() => {}}
/>
```

Composes `SeverityBadge` and `Button`. Keep titles outcome-focused (what it means), not scanner jargon. Omit `onFix`/`onMute` to hide those buttons.
