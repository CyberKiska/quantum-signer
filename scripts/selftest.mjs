import { runSelfTest } from '../src/crypto/selftest.js';

async function main() {
  const full = process.env.FULL_SELFTEST === '1';
  const report = await runSelfTest({ full });

  console.log(`Self-test: ${report.ok ? 'PASS' : 'FAIL'} (${report.passed}/${report.total}) mode=${full ? 'full' : 'quick'}`);
  for (const result of report.results) {
    if (result.ok) {
      console.log(`  OK   ${result.name}`);
    } else {
      console.log(`  FAIL ${result.name}: ${result.error}`);
    }
  }

  if (!report.ok) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
