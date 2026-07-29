import { SuiteId } from '../src/formats/containers.js';
import { createSecretSessionManager } from '../src/crypto/secret-session.js';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function allZero(bytes) {
  return bytes.every((byte) => byte === 0);
}

function createFakeScheduler() {
  let currentTime = 0;
  let nextId = 1;
  const timers = new Map();

  function setTimer(callback, delay) {
    const id = nextId++;
    timers.set(id, { callback, dueAt: currentTime + Number(delay) });
    return id;
  }

  function clearTimer(id) {
    timers.delete(id);
  }

  function advance(milliseconds) {
    const target = currentTime + milliseconds;
    while (true) {
      let selectedId = null;
      let selected = null;
      for (const [id, timer] of timers) {
        if (timer.dueAt <= target && (!selected || timer.dueAt < selected.dueAt)) {
          selectedId = id;
          selected = timer;
        }
      }
      if (!selected) break;
      currentTime = selected.dueAt;
      timers.delete(selectedId);
      selected.callback();
    }
    currentTime = target;
  }

  function elapseWithoutRunningTimers(milliseconds) {
    currentTime += milliseconds;
  }

  return {
    now: () => currentTime,
    setTimer,
    clearTimer,
    advance,
    elapseWithoutRunningTimers,
  };
}

function createTestManager(scheduler, idleTimeoutMs = 1_000, options = {}) {
  return createSecretSessionManager({
    idleTimeoutMs,
    now: scheduler.now,
    setTimer: scheduler.setTimer,
    clearTimer: scheduler.clearTimer,
    ...options,
  });
}

function testActivityExtendsExpiry() {
  const scheduler = createFakeScheduler();
  const manager = createTestManager(scheduler);
  const summary = manager.generateSession(SuiteId.ML_DSA_44);

  scheduler.advance(600);
  const session = manager.getSession(summary.sessionHandle);
  scheduler.advance(999);
  assert(manager.hasSession(summary.sessionHandle), 'active session expired before the refreshed idle deadline');

  scheduler.advance(1);
  assert(!manager.hasSession(summary.sessionHandle), 'idle session remained addressable after its deadline');
  assert(allZero(session.secretKey), 'expired idle session secret key was not wiped');
  assert(allZero(session.publicKey), 'expired idle session public key was not wiped');
}

function testExpiryDefersWipeDuringLease() {
  const scheduler = createFakeScheduler();
  const manager = createTestManager(scheduler);
  const summary = manager.generateSession(SuiteId.ML_DSA_44);
  const lease = manager.acquireSession(summary.sessionHandle);
  const { secretKey, publicKey } = lease.session;

  scheduler.advance(1_000);
  assert(!manager.hasSession(summary.sessionHandle), 'expired leased session still accepted new operations');
  assert(!allZero(secretKey), 'secret key was wiped while an active signing lease existed');
  assert(!allZero(publicKey), 'public key was wiped while an active signing lease existed');

  lease.release();
  assert(allZero(secretKey), 'deferred secret-key wipe did not run when the lease was released');
  assert(allZero(publicKey), 'deferred public-key wipe did not run when the lease was released');
}

function testLateAccessCannotReviveExpiredSession() {
  const scheduler = createFakeScheduler();
  const expiredHandles = [];
  const manager = createTestManager(scheduler, 1_000, {
    onSessionExpired: (handle) => expiredHandles.push(handle),
  });
  const summary = manager.generateSession(SuiteId.ML_DSA_44);
  const session = manager.getSession(summary.sessionHandle);

  // Simulate background-tab throttling: monotonic time advances past the
  // deadline, but the scheduled callback has not been allowed to run.
  scheduler.elapseWithoutRunningTimers(1_000);
  let rejected = false;
  try {
    manager.getSession(summary.sessionHandle);
  } catch (err) {
    rejected = err?.code === 'E_SESSION_MISSING' && err?.details?.reason === 'idle_timeout';
  }

  assert(rejected, 'late access revived a session after its idle deadline');
  assert(!manager.hasSession(summary.sessionHandle), 'synchronously expired session remained addressable');
  assert(allZero(session.secretKey), 'synchronously expired session secret key was not wiped');
  assert(
    expiredHandles.length === 1 && expiredHandles[0] === summary.sessionHandle,
    'session-expiry observer did not receive the expired handle exactly once'
  );
}

function testInvalidExportConsentDoesNotRefreshIdleDeadline() {
  const scheduler = createFakeScheduler();
  const manager = createTestManager(scheduler);
  const summary = manager.generateSession(SuiteId.ML_DSA_44);

  scheduler.advance(900);
  const authorization = manager.authorizeSecretKeyExport(summary.sessionHandle);
  let rejected = false;
  try {
    manager.exportSecretKeyFile(summary.sessionHandle, 'wrong-export-consent');
  } catch (err) {
    rejected = err?.code === 'E_EXPORT_AUTH';
  }
  assert(rejected, 'invalid export-consent token was unexpectedly accepted');

  scheduler.advance(100);
  assert(!manager.hasSession(summary.sessionHandle), 'invalid export attempt extended the idle deadline');
  assert(typeof authorization.exportConsentToken === 'string', 'export authorization did not issue a token');
}

function testExportAuthorizationIsExpiringAndOneTime() {
  const scheduler = createFakeScheduler();
  const manager = createTestManager(scheduler, 10_000, { exportAuthorizationTtlMs: 100 });
  const summary = manager.generateSession(SuiteId.ML_DSA_44);

  const firstGrant = manager.authorizeSecretKeyExport(summary.sessionHandle);
  const exported = manager.exportSecretKeyFile(summary.sessionHandle, firstGrant.exportConsentToken);
  assert(exported instanceof Uint8Array && exported.length > 0, 'authorized secret export failed');

  let replayRejected = false;
  try {
    manager.exportSecretKeyFile(summary.sessionHandle, firstGrant.exportConsentToken);
  } catch (err) {
    replayRejected = err?.code === 'E_EXPORT_AUTH';
  }
  assert(replayRejected, 'one-time export authorization was replayable');

  const expiringGrant = manager.authorizeSecretKeyExport(summary.sessionHandle);
  scheduler.advance(100);
  let expiredRejected = false;
  try {
    manager.exportSecretKeyFile(summary.sessionHandle, expiringGrant.exportConsentToken);
  } catch (err) {
    expiredRejected = err?.code === 'E_EXPORT_AUTH' && err?.details?.reason === 'expired';
  }
  assert(expiredRejected, 'expired export authorization was accepted');
}

function testSessionCapacityIsBounded() {
  const scheduler = createFakeScheduler();
  const manager = createTestManager(scheduler, 10_000, { maxSessions: 2 });
  const first = manager.generateSession(SuiteId.ML_DSA_44);
  manager.generateSession(SuiteId.ML_DSA_44);

  let limited = false;
  try {
    manager.generateSession(SuiteId.ML_DSA_44);
  } catch (err) {
    limited = err?.code === 'E_SESSION_LIMIT' && err?.details?.maxSessions === 2;
  }
  assert(limited, 'secret-session manager exceeded its configured capacity');

  manager.clearSession(first.sessionHandle);
  manager.generateSession(SuiteId.ML_DSA_44);
}

function testHasSessionEnforcesDelayedDeadlineWithoutTouching() {
  const scheduler = createFakeScheduler();
  const expiredHandles = [];
  const manager = createTestManager(scheduler, 1_000, {
    onSessionExpired: (handle) => expiredHandles.push(handle),
  });
  const summary = manager.generateSession(SuiteId.ML_DSA_44);
  const session = manager.getSession(summary.sessionHandle);

  scheduler.elapseWithoutRunningTimers(1_000);
  assert(!manager.hasSession(summary.sessionHandle), 'hasSession reported an idle-expired session as active');
  assert(allZero(session.secretKey), 'hasSession did not wipe an idle-expired session');
  assert(
    expiredHandles.length === 1 && expiredHandles[0] === summary.sessionHandle,
    'hasSession expiry did not notify the observer exactly once'
  );
}

testActivityExtendsExpiry();
testExpiryDefersWipeDuringLease();
testLateAccessCannotReviveExpiredSession();
testInvalidExportConsentDoesNotRefreshIdleDeadline();
testExportAuthorizationIsExpiringAndOneTime();
testSessionCapacityIsBounded();
testHasSessionEnforcesDelayedDeadlineWithoutTouching();
console.log('Secret-session lifecycle tests: PASS');
