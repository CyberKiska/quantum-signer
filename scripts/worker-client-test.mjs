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
const client = createWorkerClient('/assets/worker.js', {
  workerFactory() {
    const worker = new MockWorker();
    workers.push(worker);
    return worker;
  },
  setTimer: scheduler.setTimer,
  clearTimer: scheduler.clearTimer,
});

for (const invalidTimeout of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 0x80000000]) {
  const error = await client.call('HASH_TEXT', { text: 'test' }, { timeoutMs: invalidTimeout }).catch((err) => err);
  assert(error instanceof RangeError, `invalid timeout was not rejected: ${String(invalidTimeout)}`);
}
assert(workers[0].messages.length === 0, 'invalid timeout posted a request to the worker');

// Progress is delivered only to the matching request, then the result resolves it.
const progress = [];
const hashed = client.call('HASH_FILE', { file: {} }, { timeoutMs: 200, onProgress: (msg) => progress.push(msg.percent) });
const hashRequest = workers[0].messages.at(-1);
workers[0].respond({ id: 'unrelated', type: 'PROGRESS', percent: 99 });
workers[0].respond({ id: hashRequest.id, type: 'PROGRESS', percent: 50 });
workers[0].respond({ id: hashRequest.id, type: 'RESULT', result: { hashHex: '00' } });
assert((await hashed)?.hashHex === '00' && progress.join() === '50', 'progress/result routing failed');

// Worker errors keep their catalogued code.
const failing = client.call('VERIFY_TEXT', {}, { timeoutMs: 200 }).then(() => null, (err) => err);
workers[0].respond({ id: workers[0].messages.at(-1).id, type: 'ERROR', code: 'E_FORMAT_MAGIC', message: 'Invalid file magic header.' });
assert((await failing)?.code === 'E_FORMAT_MAGIC', 'worker error code was not preserved');

// A timeout terminates the busy worker (it holds no secrets) and fails every
// pending request; the next call starts exactly one fresh worker.
const timedCall = client.call('VERIFY_FILE', {}, { timeoutMs: 100 }).then(() => null, (err) => err);
const bystander = client.call('HASH_TEXT', { text: 'x' }, { timeoutMs: 1_000 }).then(() => null, (err) => err);
const timedRequest = workers[0].messages.at(-2);
scheduler.advance(100);
const timeoutError = await timedCall;
assert(timeoutError?.message.includes('Operation timed out after 100ms'), 'timed operation returned the wrong error');
assert(workers[0].terminated, 'timed-out worker was left running and busy');
assert((await bystander) instanceof Error, 'requests on the timed-out worker were not failed');
assert(workers.length === 1, 'timeout eagerly constructed a replacement worker');
// A late message from the terminated worker must not resolve anything.
workers[0].respond({ id: timedRequest.id, type: 'RESULT', result: { stale: true } });

const afterTimeout = client.call('HASH_TEXT', { text: 'fresh' }, { timeoutMs: 200 });
assert(workers.length === 2, 'next call did not lazily create one replacement worker');
workers[1].respond({ id: workers[1].messages.at(-1).id, type: 'RESULT', result: { ok: true } });
assert((await afterTimeout)?.ok === true, 'replacement worker did not serve requests');

// Asynchronous worker failure: terminate, reject, and do not restart in a loop.
const failedCall = client.call('HASH_TEXT', { text: 'worker-failure' }, { timeoutMs: 200 }).then(() => null, (err) => err);
workers[1].onerror?.(new Error('synthetic worker load failure'));
assert((await failedCall)?.message === 'Cryptographic worker failed', 'worker failure returned the wrong error');
assert(workers[1].terminated, 'failed worker was not terminated');
workers[1].onerror?.(new Error('repeated synthetic worker failure'));
assert(workers.length === 2, 'asynchronous failure caused a restart loop');

const lastCall = client.call('HASH_TEXT', { text: 'x' }, { timeoutMs: 200 }).then(() => null, (err) => err);
assert(workers.length === 3, 'next call after failure did not create one replacement worker');
client.destroy();
assert(workers[2].terminated, 'replacement worker was not terminated on client destroy');
assert((await lastCall)?.message === 'Cryptographic worker was terminated', 'destroy did not reject pending calls');
assert((await client.call('HASH_TEXT', {}).catch((err) => err))?.message.includes('destroyed'), 'destroyed client accepted a call');
console.log('Worker-client lifecycle tests: PASS');
