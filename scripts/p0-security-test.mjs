import {
  buildLegacyDisplayMetadataReviewGroup,
  renderReviewGroups,
  safeReviewText,
} from '../src/ui/common.js';
import { resolveSignInputKind } from '../src/core/sign-input.js';
import { ErrorCode } from '../src/crypto/errors.js';

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

const legacyGroup = buildLegacyDisplayMetadataReviewGroup(
  {
    filename: hostileText,
    filesize: '41',
    createdAt: '2025-01-01T00:00:00.000Z',
  },
  42
);
assert(legacyGroup?.tone === 'untrusted', 'legacy display metadata was not marked untrusted');
assert(
  legacyGroup.rows.some((row) => row.label === 'Mismatch warning' && row.tone === 'warning'),
  'legacy display file-size mismatch was not made explicit'
);

const document = new TestDocument();
const container = new TestNode('div', document);
renderReviewGroups(container, [
  {
    title: 'Authenticated fields',
    rows: [{ label: 'Digest', value: 'abcd' }],
  },
  legacyGroup,
]);

const renderedNodes = descendants(container);
assert(
  renderedNodes.some((node) => node.className.split(' ').includes('untrusted')),
  'legacy display metadata was not isolated in an untrusted DOM section'
);
assert(
  renderedNodes.filter((node) => node.tagName === 'dd').length === 5,
  'review values were not rendered as separate DOM fields'
);
assert(!container.textContent.includes('\u2028'), 'rendered review retained U+2028');
assert(container.textContent.includes('<U+2028>'), 'rendered review did not expose escaped U+2028');

assert(resolveSignInputKind({ file: {} }) === 'file', 'file-only sign input was not accepted');
assert(resolveSignInputKind({ text: 'message' }) === 'text', 'text-only sign input was not accepted');

let ambiguousError = null;
try {
  resolveSignInputKind({ file: {}, text: 'message' });
} catch (error) {
  ambiguousError = error;
}
assert(ambiguousError?.code === ErrorCode.E_WORKER_PROTOCOL, 'ambiguous sign input returned the wrong error');
assert(
  ambiguousError?.details?.reason === 'mutually_exclusive_inputs',
  'ambiguous sign input returned the wrong protocol reason'
);

let missingError = null;
try {
  resolveSignInputKind({});
} catch (error) {
  missingError = error;
}
assert(missingError?.code === ErrorCode.E_INPUT_REQUIRED, 'missing sign input returned the wrong error');

console.log('P0 display-integrity and sign-protocol tests: PASS');
