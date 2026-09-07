/**
 * A DOM small enough to run verify.html, and no smaller.
 *
 * The page is the deliverable, not the module behind it: a verifier that
 * computes the right answer and then throws while rendering it has verified
 * nothing. Running the real page against a stub is how that stays true without
 * a browser in CI.
 *
 * Only what the template touches is implemented. Anything it starts using that
 * is missing here throws, which is the intended failure — the stub is a list of
 * the DOM surface the page is allowed to depend on.
 */

class ClassList {
  constructor(el) {
    this.el = el;
  }

  add(name) {
    const set = new Set(String(this.el.className).split(/\s+/).filter(Boolean));
    set.add(name);
    this.el.className = [...set].join(' ');
  }

  remove(name) {
    const set = new Set(String(this.el.className).split(/\s+/).filter(Boolean));
    set.delete(name);
    this.el.className = [...set].join(' ');
  }

  toggle(name) {
    const set = new Set(String(this.el.className).split(/\s+/).filter(Boolean));
    if (set.has(name)) set.delete(name);
    else set.add(name);
    this.el.className = [...set].join(' ');
  }

  contains(name) {
    return String(this.el.className).split(/\s+/).includes(name);
  }
}

class Element {
  constructor(tag, doc) {
    this.tagName = String(tag).toUpperCase();
    this.doc = doc;
    this.children = [];
    this.parentElement = null;
    this.style = {};
    this.className = '';
    this._html = '';
    this._text = '';
    this.classList = new ClassList(this);
    this.listeners = {};
  }

  set innerHTML(value) {
    this._html = String(value);
  }

  get innerHTML() {
    return this._html;
  }

  set textContent(value) {
    this._text = String(value);
  }

  get textContent() {
    return this._text;
  }

  appendChild(child) {
    child.parentElement = this;
    this.children.push(child);
    return child;
  }

  addEventListener(name, fn) {
    (this.listeners[name] ||= []).push(fn);
  }

  querySelectorAll() {
    return [];
  }

  /** Everything this element and its children rendered, flattened. */
  rendered() {
    return [this._html, this._text, ...this.children.map((c) => c.rendered())].join('\n');
  }
}

class Document {
  constructor(ids) {
    this.byId = new Map();
    for (const id of ids) this.byId.set(id, new Element('div', this));
  }

  getElementById(id) {
    if (!this.byId.has(id)) this.byId.set(id, new Element('div', this));
    return this.byId.get(id);
  }

  createElement(tag) {
    return new Element(tag, this);
  }

  querySelectorAll() {
    return [];
  }

  /** Every id the page wrote to, with what it wrote. */
  dump() {
    const out = {};
    for (const [id, el] of this.byId) out[id] = el.rendered();
    return out;
  }
}

/**
 * Run a rendered verify.html page against the stub. Returns the document, the
 * ids it wrote to, and anything it threw.
 */
export async function runPage(html) {
  const script = html.slice(
    html.lastIndexOf('<script>') + '<script>'.length,
    html.lastIndexOf('</script>'),
  );
  const ids = [...html.matchAll(/id="([a-z0-9-]+)"/g)].map((m) => m[1]);
  const document = new Document(ids);
  let thrown = null;
  const done = new Promise((resolve) => {
    globalThis.__pageDone = resolve;
    globalThis.__pageFailed = (e) => {
      thrown = e;
      resolve();
    };
  });
  const patched =
    script.replace(
      /run\(\)\.catch\(\(e\) => \{/,
      'run().then(() => __pageDone()).catch((e) => { __pageFailed(e);',
    ) + '\n';
  const fn = new Function('document', 'window', patched);
  fn(document, { document });
  await done;
  return { document, thrown, ids: document.dump() };
}
