// Example custom detector plugin for scan-secrets
// Exports one detector for all files under this directory.

function scan(context) {
  const findings = [];

  for (let i = 0; i < context.lines.length; i++) {
    const line = context.lines[i];
    const match = line.match(/TODO\s+SECRET\s*=\s*([A-Za-z0-9_-]{12,})/i);
    if (!match) continue;

    findings.push({
      rule_id: 'custom-todo-secret',
      rule_name: 'TODO Secret Marker',
      severity: 'medium',
      line: i + 1,
      column: match.index + 1,
      match: match[1],
      snippet: line,
      detector: 'custom-plugin',
    });
  }

  return findings;
}

module.exports = {
  id: 'todo-secret-plugin',
  name: 'Todo Secret Detector',
  scan,
};
