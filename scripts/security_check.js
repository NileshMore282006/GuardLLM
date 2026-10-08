/**
 * AgentGuard Frontend Static Security Checks (Frontend v0.7)
 * Scans frontend source files (`src/**`) for dangerous credential persistence,
 * unauthorized browser storage access, and sensitive token leakage.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SRC_DIR = path.resolve(__dirname, '../src');

// Regex rules for security invariant violations
const SECURITY_RULES = [
  {
    id: 'SEC-001',
    description: 'Direct use of localStorage for tokens or credentials',
    pattern: /localStorage\s*\.\s*(setItem|getItem)\s*\(\s*['"`].*(token|auth|credential|secret|bearer).*['"`]/i,
  },
  {
    id: 'SEC-002',
    description: 'Direct use of sessionStorage for tokens or credentials',
    pattern: /sessionStorage\s*\.\s*(setItem|getItem)\s*\(\s*['"`].*(token|auth|credential|secret|bearer).*['"`]/i,
  },
  {
    id: 'SEC-003',
    description: 'Writing credentials or tokens to document.cookie',
    pattern: /document\s*\.\s*cookie\s*=.*(token|auth|credential|secret|bearer)/i,
  },
  {
    id: 'SEC-004',
    description: 'Logging raw Authorization header or Bearer token to console',
    pattern: /console\s*\.\s*(log|warn|info|debug)\s*\(.*(Authorization|Bearer\s|developerToken|adminToken)/i,
  },
  {
    id: 'SEC-005',
    description: 'Interpolating raw token into URL query string in fetch',
    pattern: /fetch\s*\(.*[?&](token|api_key|secret)=\${/i,
  },
];

function scanDirectory(dir, findings = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== '__tests__') {
        scanDirectory(fullPath, findings);
      }
    } else if (entry.isFile() && (entry.name.endsWith('.ts') || entry.name.endsWith('.tsx') || entry.name.endsWith('.js'))) {
      const content = fs.readFileSync(fullPath, 'utf8');
      const lines = content.split('\n');

      lines.forEach((line, index) => {
        // Skip comment lines
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
          return;
        }

        for (const rule of SECURITY_RULES) {
          if (rule.pattern.test(line)) {
            findings.push({
              file: path.relative(SRC_DIR, fullPath),
              line: index + 1,
              ruleId: rule.id,
              description: rule.description,
              snippet: line.trim(),
            });
          }
        }
      });
    }
  }

  return findings;
}

export function runSecurityChecks() {
  const findings = scanDirectory(SRC_DIR);
  return findings;
}

// If executed directly from command line
if (process.argv[1] === __filename) {
  console.log('Running AgentGuard Frontend Static Security Checks...');
  const findings = runSecurityChecks();

  if (findings.length > 0) {
    console.error(`\x1b[31mFAIL: Found ${findings.length} security rule violation(s):\x1b[0m`);
    findings.forEach((f) => {
      console.error(`  [${f.ruleId}] ${f.file}:${f.line} - ${f.description}`);
      console.error(`      Snippet: ${f.snippet}`);
    });
    process.exit(1);
  } else {
    console.log('\x1b[32mPASS: Zero dangerous storage or token exposure patterns found.\x1b[0m');
    process.exit(0);
  }
}
