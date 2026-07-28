import { createWorkerClient } from '../src/ui/common.js';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function createFakeScheduler() {
  let now = 0;
  let nextId = 1;
  const timers = new Map();

  function setTimer(callback, delay) {
    const id = nextId++;
    timers.set(id, { callback, dueAt: now + Number(delay) });
    return id;
  }

  function clearTimer(id) {
    timers.delete(id);
  }

  function advance(milliseconds) {
    const target = now + milliseconds;
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
      now = selected.dueAt;
      timers.delete(selectedId);
      selected.callback();
    }
    now = target;
  }

  return { setTimer, clearTimer, advance };
}

class MockWorker {
  constructor() {
    this.messages = [];
    this.terminated = false;
    this.onmessage = null;
    this.onerror = null;
    this.onmessageerror = null;
  }

  postMessage(message) {
    if (this.terminated) throw new Error('postMessage called after termination');
    this.messages.push(message);
  }

  terminate() {
    this.terminated = true;
  }

  respond(data) {
    this.onmessage?.({ data });
  }
}

const scheduler = createFakeScheduler();
const workers = [];
const invalidations = [];
const client = createWorkerClient('/assets/worker.js', {
  workerFactory() {
    const worker = new MockWorker();
    workers.push(worker);
    return worker;
  },
  setTimer: scheduler.setTimer,
  clearTimer: scheduler.clearTimer,
});
client.onSecretSessionInvalidated((event) => invalidations.push(event));

for (const invalidTimeout of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 0x80000000]) {
  const error = await client.call('HASH_TEXT', { text: 'test' }, { timeoutMs: invalidTimeout }).catch((err) => err);
  assert(error instanceof RangeError, `invalid timeout was not rejected: ${String(invalidTimeout)}`);
}
assert(workers[0].messages.length === 0, 'invalid timeout posted a request to the worker');

const timedCall = client
  .call('SIGN', { secretSessionHandle: 'session-a' }, { timeoutMs: 100 })
  .then(() => null, (err) => err);
const concurrentCall = client.call('HASH_FILE', { file: {} }, { timeoutMs: 200 });

scheduler.advance(100);
const timeoutError = await timedCall;
assert(timeoutError?.message.includes('Operation timed out after 100ms'), 'timed operation returned the wrong error');
assert(timeoutError?.message.includes('left running'), 'timeout did not explain private-key preservation');
assert(workers.length === 1, 'timeout unexpectedly constructed a replacement worker');
assert(!workers[0].terminated, 'timeout destroyed the key-holding worker');
assert(invalidations.length === 0, 'timeout unexpectedly invalidated secret-session capabilities');

const concurrentRequest = workers[0].messages.at(-1);
workers[0].respond({
  id: concurrentRequest.id,
  type: 'RESULT',
  result: { hashHex: '00' },
});
assert((await concurrentCall)?.hashHex === '00', 'concurrent request did not survive another call timing out');

// A late result for the timed-out operation must be ignored rather than
// resolving old UI state.
const timedRequest = workers[0].messages[0];
workers[0].respond({ id: timedRequest.id, type: 'RESULT', result: { stale: true } });

const failedCall = client
  .call('HASH_TEXT', { text: 'worker-failure' }, { timeoutMs: 200 })
  .then(() => null, (err) => err);
workers[0].onerror?.(new Error('synthetic worker load failure'));
const workerFailure = await failedCall;
assert(workerFailure?.message === 'Cryptographic worker failed', 'worker failure returned the wrong error');
assert(workers[0].terminated, 'failed worker was not terminated');
assert(workers.length === 1, 'asynchronous failure caused an eager worker restart');
workers[0].onerror?.(new Error('repeated synthetic worker failure'));
assert(workers.length === 1, 'repeated asynchronous failure caused a restart loop');
assert(
  invalidations.some((event) => event.reason === 'worker-failed' && event.restarted === false),
  'worker failure did not invalidate secret-session capabilities'
);

const missingCall = client
  .call('EXPORT_SECRET', { secretSessionHandle: 'session-b', exportConsentToken: 'token' })
  .then(() => null, (err) => err);
assert(workers.length === 2, 'next explicit call did not lazily create one replacement worker');
const missingRequest = workers[1].messages.at(-1);
workers[1].respond({
  id: missingRequest.id,
  type: 'ERROR',
  code: 'E_SESSION_MISSING',
  message: 'Secret session not found or already cleared.',
});
const missingError = await missingCall;
assert(missingError?.code === 'E_SESSION_MISSING', 'session-missing worker error was not preserved');
assert(
  invalidations.some(
    (event) => event.reason === 'session-missing' && event.sessionHandle === 'session-b'
  ),
  'session-missing error did not surface the invalid secret-session handle'
);

workers[1].respond({
  type: 'SECRET_SESSION_INVALIDATED',
  reason: 'idle-timeout',
  secretSessionHandle: 'session-c',
});
assert(
  invalidations.some(
    (event) => event.reason === 'idle-timeout' && event.sessionHandle === 'session-c'
  ),
  'proactive worker expiry event was not surfaced'
);

client.destroy();
assert(workers[1].terminated, 'replacement worker was not terminated on client destroy');
console.log('Worker-client lifecycle tests: PASS');
