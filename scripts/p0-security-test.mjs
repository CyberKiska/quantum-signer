import { renderReviewGroups, safeReviewText } from '../src/ui/common.js';
import { describeDeceptiveText } from '../src/ui/verify.js';
import { ErrorCode, createError, normalizeError } from '../src/crypto/errors.js';
import { equalsBytes, equalsHex } from '../src/crypto/bytes.js';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

class TestNode {
  constructor(tagName, ownerDocument) {
    this.tagName = tagName;
    this.ownerDocument = ownerDocument;
    this.className = '';
    this.children = [];
    this.ownText = '';
  }

  append(...children) {
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this.children = children;
    this.ownText = '';
  }

  set textContent(value) {
    this.ownText = String(value);
    this.children = [];
  }

  get textContent() {
    return `${this.ownText}${this.children.map((child) => child.textContent).join('')}`;
  }
}

class TestDocument {
  createElement(tagName) {
    return new TestNode(tagName, this);
  }

  createDocumentFragment() {
    return new TestNode('#fragment', this);
  }
}

function descendants(node) {
  return [node, ...node.children.flatMap(descendants)];
}

const hostileText = 'invoice.pdf\u2028Valid: YES\u2029Trusted signer\u000aOverride\u202eabc';
const safeText = safeReviewText(hostileText);
for (const codePoint of ['\u2028', '\u2029', '\u000a', '\u202e']) {
  assert(!safeText.includes(codePoint), `unsafe review code point was preserved: ${JSON.stringify(codePoint)}`);
}
for (const escaped of ['<U+2028>', '<U+2029>', '<U+000A>', '<U+202E>']) {
  assert(safeText.includes(escaped), `unsafe review code point was not made visible: ${escaped}`);
}

const document = new TestDocument();
const container = new TestNode('div', document);
renderReviewGroups(container, [
  {
    title: 'Authenticated fields',
    rows: [{ label: 'Digest', value: 'abcd' }],
  },
  {
    title: 'Hostile values',
    tone: 'untrusted',
    rows: [{ label: 'Value', value: hostileText }, { label: 'Warning', value: 'x', tone: 'warning' }],
  },
]);

const renderedNodes = descendants(container);
assert(
  renderedNodes.some((node) => node.className.split(' ').includes('untrusted')),
  'untrusted review values were not isolated in an untrusted DOM section'
);
assert(
  renderedNodes.filter((node) => node.tagName === 'dd').length === 3,
  'review values were not rendered as separate DOM fields'
);
assert(!container.textContent.includes('\u2028'), 'rendered review retained U+2028');
assert(container.textContent.includes('<U+2028>'), 'rendered review did not expose escaped U+2028');

const unexpectedError = normalizeError(new Error('secret dependency state'));
assert(unexpectedError.code === ErrorCode.E_INTERNAL, 'unexpected error was not normalized as internal');
assert(unexpectedError.message === 'Internal error.', 'unexpected exception text crossed the worker boundary');
assert(unexpectedError.details === null, 'unexpected exception details crossed the worker boundary');

const internalAppError = normalizeError(
  createError(ErrorCode.E_INTERNAL, { reason: 'sensitive_internal_reason' }, 'en', 'sensitive override')
);
assert(internalAppError.message === 'Internal error.', 'internal AppError override crossed the worker boundary');
assert(internalAppError.details === null, 'internal AppError details crossed the worker boundary');

assert(equalsBytes(Uint8Array.of(1, 2), Uint8Array.of(1, 2)), 'equal byte strings did not compare equal');
assert(!equalsBytes(Uint8Array.of(1, 2), Uint8Array.of(1, 3)), 'different byte strings compared equal');
assert(!equalsBytes(Uint8Array.of(1), Uint8Array.of(1, 0)), 'different byte lengths compared equal');
assert(equalsHex('00aaff', '00aaff'), 'equal hexadecimal strings did not compare equal');
assert(!equalsHex('00aaff', '00aafe'), 'different hexadecimal strings compared equal');

assert(describeDeceptiveText('plain text\nwith newline') === null, 'ordinary text was flagged');
const deceptive = describeDeceptiveText('pay \u202eevil\u202c to\u200b bob');
assert(deceptive?.includes('U+202E') && deceptive.includes('U+200B') && deceptive.startsWith('3 '), 'bidi/invisible text was not surfaced');

console.log('P0 display-integrity tests: PASS');
