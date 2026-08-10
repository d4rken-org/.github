'use strict'

// Run with: node --test .github/thumbnail/
// Covers the parsing and validation logic. The network probe is not exercised.

const test = require('node:test')
const assert = require('node:assert')

const { rewrite, allowedUrl, thumbnailWidth, codeLineIndices, escapeAttr } = require('./rewrite')

const ATTACHMENT = 'https://github.com/user-attachments/assets/0e3b1f2a-1111-2222-3333-444455556666'
const ATTACHMENT2 = 'https://github.com/user-attachments/assets/9a9a9a9a-5555-6666-7777-888899990000'

// Stands in for the network probe. 1080x2400 is a typical phone screenshot and
// yields width=180.
const tallProbe = { probe: async () => ({ width: 1080, height: 2400 }) }

// HTML tags declare their own size, so any probe on such a body is a bug.
const noProbe = {
  probe: async (url) => {
    throw new Error(`probe must not run for HTML tags, got ${url}`)
  },
}

const attachment = (n) =>
  `https://github.com/user-attachments/assets/aaaaaaaa-bbbb-cccc-dddd-00000000000${n}`

test('rewrite replaces an eligible image with a clickable thumbnail', async () => {
  const result = await rewrite(`before\n\n![my "shot" & co](${ATTACHMENT})\n\nafter`, tallProbe)
  assert.strictEqual(result.changed, true)
  assert.strictEqual(
    result.body,
    'before\n\n' +
      `<a href="${ATTACHMENT}"><img src="${ATTACHMENT}" alt="my &quot;shot&quot; &amp; co" width="180"></a>` +
      '\n\nafter',
  )
  // Quotes in the alt text must not break out of the attribute.
  assert.ok(!result.body.includes('alt="my "shot"'))
  // Height is never emitted: with width it fights GitHub's max-width:100%.
  assert.ok(!result.body.includes('height='))
})

test('rewrite handles several images on one line without corrupting offsets', async () => {
  const result = await rewrite(`![a](${ATTACHMENT}) middle ![b](${ATTACHMENT2})`, tallProbe)
  assert.strictEqual(result.changed, true)
  assert.strictEqual(
    result.body,
    `<a href="${ATTACHMENT}"><img src="${ATTACHMENT}" alt="a" width="180"></a>` +
      ' middle ' +
      `<a href="${ATTACHMENT2}"><img src="${ATTACHMENT2}" alt="b" width="180"></a>`,
  )
})

test('rewrite is idempotent: its own output does not rematch', async () => {
  const once = await rewrite(`![a](${ATTACHMENT})`, tallProbe)
  assert.strictEqual(once.changed, true)
  const twice = await rewrite(once.body, tallProbe)
  assert.strictEqual(twice.changed, false)
})

test('rewrite leaves escaped and already-linked images alone', async () => {
  // Escaped: not an image at all.
  const escaped = `\\![shot](${ATTACHMENT})`
  assert.deepStrictEqual(await rewrite(escaped, tallProbe), { changed: false, body: escaped })

  // Already a linked image: rewriting would discard the author's link target.
  const linked = `[![shot](${ATTACHMENT})](https://example.com/details)`
  assert.deepStrictEqual(await rewrite(linked, tallProbe), { changed: false, body: linked })
})

test('rewrite ignores images in a fence opened inside a list item', async () => {
  const body = ['- example:', '  ```md', `  ![shot](${ATTACHMENT})`, '  ```', '', 'prose'].join('\n')
  assert.deepStrictEqual(await rewrite(body, tallProbe), { changed: false, body })
})

test('a stray fence in a list does not hide later real images', async () => {
  const body = ['- ```md', '  sample', '  ```', '', `![real](${ATTACHMENT})`].join('\n')
  const result = await rewrite(body, tallProbe)
  assert.strictEqual(result.changed, true)
  assert.ok(result.body.includes('<img src='), 'image after the list fence should still be rewritten')
  assert.ok(result.body.includes('  sample'), 'the fenced sample must be untouched')
})

test('rewrite skips images whose probe fails', async () => {
  const body = `![shot](${ATTACHMENT})`
  const failing = { probe: async () => null }
  assert.deepStrictEqual(await rewrite(body, failing), { changed: false, body })
})

test('allowedUrl accepts GitHub attachment hosts', () => {
  assert.strictEqual(allowedUrl(ATTACHMENT), ATTACHMENT)
  assert.strictEqual(
    allowedUrl('https://user-images.githubusercontent.com/1/2.png'),
    'https://user-images.githubusercontent.com/1/2.png',
  )
})

test('allowedUrl rejects lookalike and non-GitHub hosts', () => {
  // Suffix confusion: passes a naive includes('github.com') check.
  assert.strictEqual(allowedUrl('https://github.com.evil.tld/user-attachments/assets/x'), null)
  // Fragment confusion: also passes a naive includes() check.
  assert.strictEqual(allowedUrl('https://evil.tld/x.png#github.com'), null)
  // Subdomain that is not on the list.
  assert.strictEqual(allowedUrl('https://raw.githubusercontent.com/o/r/main/x.png'), null)
  // Wrong path on an allowed host.
  assert.strictEqual(allowedUrl('https://github.com/owner/repo/raw/main/x.png'), null)
  // Path traversal is normalised by URL parsing before the prefix check.
  assert.strictEqual(allowedUrl('https://github.com/user-attachments/assets/../../x.png'), null)
  // Non-https schemes.
  assert.strictEqual(allowedUrl('http://github.com/user-attachments/assets/x'), null)
  assert.strictEqual(allowedUrl('file:///etc/passwd'), null)
  // Embedded credentials.
  assert.strictEqual(allowedUrl('https://u:p@github.com/user-attachments/assets/x'), null)
  // Cloud metadata endpoint.
  assert.strictEqual(allowedUrl('http://169.254.169.254/metadata/instance'), null)
  assert.strictEqual(allowedUrl('not a url'), null)
})

test('escapeAttr neutralises attribute breakout', () => {
  assert.strictEqual(
    escapeAttr('" onerror="alert(1)'),
    '&quot; onerror=&quot;alert(1)',
  )
  assert.strictEqual(escapeAttr('a & b <c>'), 'a &amp; b &lt;c&gt;')
})

test('thumbnailWidth only shrinks tall portrait images', () => {
  assert.strictEqual(thumbnailWidth({ width: 1080, height: 2400 }), 180)
  // Landscape is already constrained by the comment column.
  assert.strictEqual(thumbnailWidth({ width: 1920, height: 1080 }), null)
  // Portrait but small enough already.
  assert.strictEqual(thumbnailWidth({ width: 200, height: 400 }), null)
  // Would scale up rather than down.
  assert.strictEqual(thumbnailWidth({ width: 100, height: 700 }), null)
})

test('thumbnailWidth rejects non-numeric dimensions from the parser', () => {
  // The image bytes are attacker-controlled, so nothing the parser reports is
  // assumed to be a number. NaN previously slipped through: every comparison
  // against it is false, so it satisfied both bounds checks.
  for (const bad of ['1 onerror=alert(1)', {}, null, undefined, NaN, Infinity, -1, 0]) {
    assert.strictEqual(thumbnailWidth({ width: bad, height: 5000 }), null, `width=${String(bad)}`)
    assert.strictEqual(thumbnailWidth({ width: 1080, height: bad }), null, `height=${String(bad)}`)
  }
})

test('codeLineIndices marks fenced and indented blocks', () => {
  const lines = [
    'before',
    '```yaml',
    'inside fence',
    '```',
    'after',
    '',
    '    indented code',
    '    still code',
    '',
    'prose again',
  ]
  const marked = codeLineIndices(lines)
  assert.deepStrictEqual([...marked].sort((a, b) => a - b), [1, 2, 3, 6, 7])
})

test('rewrite honours the opt-out marker', async () => {
  const body = `<!-- no-thumbnail -->\n![shot](${ATTACHMENT})`
  assert.deepStrictEqual(await rewrite(body), { changed: false, body })
})

test('rewrite ignores images inside fenced code blocks', async () => {
  const body = ['```md', `![shot](${ATTACHMENT})`, '```'].join('\n')
  assert.deepStrictEqual(await rewrite(body), { changed: false, body })
})

test('rewrite ignores images inside inline code spans', async () => {
  const body = `use \`![shot](${ATTACHMENT})\` to embed`
  assert.deepStrictEqual(await rewrite(body), { changed: false, body })
})

test('rewrite ignores non-allowlisted hosts', async () => {
  const body = '![shot](https://evil.tld/huge.png)'
  assert.deepStrictEqual(await rewrite(body), { changed: false, body })
})

test('rewrite ignores reference-style images and existing HTML', async () => {
  const refStyle = '![shot][ref]\n\n[ref]: ' + ATTACHMENT
  assert.deepStrictEqual(await rewrite(refStyle), { changed: false, body: refStyle })

  const html = `<a href="${ATTACHMENT}"><img src="${ATTACHMENT}" width="180"></a>`
  assert.deepStrictEqual(await rewrite(html), { changed: false, body: html })
})

// The shape GitHub's uploader emits today, as seen on sdmaid-se#2632.
const uploaded = (url, width, height, alt = 'Image') =>
  `<img width="${width}" height="${height}" alt="${alt}" src="${url}" />`

test('rewrite replaces a GitHub-emitted img tag with a clickable thumbnail', async () => {
  const result = await rewrite(`before\n\n${uploaded(ATTACHMENT, 3000, 4000)}\n\nafter`, noProbe)
  assert.strictEqual(result.changed, true)
  assert.strictEqual(
    result.body,
    'before\n\n' +
      `<a href="${ATTACHMENT}"><img src="${ATTACHMENT}" alt="Image" width="300"></a>` +
      '\n\nafter',
  )
  // The declared height must not survive: with width it fights max-width:100%.
  assert.ok(!result.body.includes('height='))
})

test('rewrite derives the tag width from the declared aspect ratio', async () => {
  const result = await rewrite(uploaded(ATTACHMENT, 1080, 2424), noProbe)
  assert.strictEqual(result.changed, true)
  assert.ok(result.body.includes('width="178"'), result.body)
})

test('rewrite leaves tags that are not oversized portraits alone', async () => {
  const landscape = uploaded(ATTACHMENT, 4000, 3000)
  assert.deepStrictEqual(await rewrite(landscape, noProbe), { changed: false, body: landscape })

  const small = uploaded(ATTACHMENT, 400, 600)
  assert.deepStrictEqual(await rewrite(small, noProbe), { changed: false, body: small })
})

test('rewrite leaves tags without both dimensions alone', async () => {
  const noWidth = `<img height="4000" alt="Image" src="${ATTACHMENT}" />`
  assert.deepStrictEqual(await rewrite(noWidth, noProbe), { changed: false, body: noWidth })

  const noHeight = `<img width="3000" alt="Image" src="${ATTACHMENT}" />`
  assert.deepStrictEqual(await rewrite(noHeight, noProbe), { changed: false, body: noHeight })
})

test('rewrite ignores tags pointing at non-allowlisted hosts', async () => {
  const body = uploaded('https://evil.tld/huge.png', 3000, 4000)
  assert.deepStrictEqual(await rewrite(body, noProbe), { changed: false, body })
})

test('rewrite ignores tags inside code', async () => {
  const fenced = ['```html', uploaded(ATTACHMENT, 3000, 4000), '```'].join('\n')
  assert.deepStrictEqual(await rewrite(fenced, noProbe), { changed: false, body: fenced })

  const inline = `embed \`${uploaded(ATTACHMENT, 3000, 4000)}\` like this`
  assert.deepStrictEqual(await rewrite(inline, noProbe), { changed: false, body: inline })
})

test('rewrite leaves already-linked tags alone and is idempotent', async () => {
  // Both dimensions present, so only the anchor makes this ineligible.
  const wrapped = `<a href="https://example.com/details">${uploaded(ATTACHMENT, 1080, 2400)}</a>`
  assert.deepStrictEqual(await rewrite(wrapped, noProbe), { changed: false, body: wrapped })

  const ownOutput = `<a href="${ATTACHMENT}"><img src="${ATTACHMENT}" alt="Image" width="300"></a>`
  assert.deepStrictEqual(await rewrite(ownOutput, noProbe), { changed: false, body: ownOutput })

  const once = await rewrite(uploaded(ATTACHMENT, 3000, 4000), noProbe)
  assert.strictEqual(once.changed, true)
  assert.deepStrictEqual(await rewrite(once.body, noProbe), { changed: false, body: once.body })
})

test('rewrite accepts tag attributes in any order', async () => {
  const body = `<img src="${ATTACHMENT}" width="3000" height="4000" alt="Image">`
  const result = await rewrite(body, noProbe)
  assert.strictEqual(result.changed, true)
  assert.ok(result.body.includes('width="300"'), result.body)
})

test('rewrite decodes tag attributes before reusing them', async () => {
  const alt = await rewrite(`<img width="1080" height="2400" alt="a &amp; b" src="${ATTACHMENT}">`, noProbe)
  assert.strictEqual(alt.changed, true)
  assert.ok(alt.body.includes('alt="a &amp; b"'), alt.body)
  assert.ok(!alt.body.includes('&amp;amp;'))

  // An encoded "&" in a query string is part of the URL, so it has to be
  // decoded before the host check and re-escaped exactly once on the way out.
  const query = await rewrite(
    `<img width="1080" height="2400" alt="x" src="${ATTACHMENT}?a=1&amp;b=2">`,
    noProbe,
  )
  assert.strictEqual(query.changed, true)
  assert.ok(query.body.includes(`href="${ATTACHMENT}?a=1&amp;b=2"`), query.body)
  assert.ok(!query.body.includes('&amp;amp;'))
})

test('rewrite resolves overlaps between the two syntaxes', async () => {
  // A Markdown image inside a tag's alt value: only the tag is rewritten, and
  // nothing is spliced into the middle of it.
  const inAlt = `<img width="1080" height="2400" alt="![a](${ATTACHMENT2})" src="${ATTACHMENT}">`
  const outer = await rewrite(inAlt, noProbe)
  assert.strictEqual(outer.changed, true)
  assert.strictEqual(
    outer.body,
    `<a href="${ATTACHMENT}"><img src="${ATTACHMENT}" alt="![a](${ATTACHMENT2})" width="180"></a>`,
  )

  // The reverse containment: only the outer Markdown image is rewritten.
  const inMarkdown = `![before ${uploaded(ATTACHMENT2, 1080, 2400, 'x')} after](${ATTACHMENT})`
  const inner = await rewrite(inMarkdown, tallProbe)
  assert.strictEqual(inner.changed, true)
  assert.strictEqual(
    inner.body,
    `<a href="${ATTACHMENT}"><img src="${ATTACHMENT}" ` +
      `alt="before &lt;img width=&quot;1080&quot; height=&quot;2400&quot; alt=&quot;x&quot; ` +
      `src=&quot;${ATTACHMENT2}&quot; /&gt; after" width="180"></a>`,
  )
})

test('rewrite handles both syntaxes on one line without corrupting offsets', async () => {
  const result = await rewrite(`![a](${ATTACHMENT}) and ${uploaded(ATTACHMENT2, 3000, 4000)}`, tallProbe)
  assert.strictEqual(result.changed, true)
  assert.strictEqual(
    result.body,
    `<a href="${ATTACHMENT}"><img src="${ATTACHMENT}" alt="a" width="180"></a>` +
      ' and ' +
      `<a href="${ATTACHMENT2}"><img src="${ATTACHMENT2}" alt="Image" width="300"></a>`,
  )
})

test('rewrite only touches tags matching the uploader grammar', async () => {
  const cases = {
    // Single quotes: the author hand-wrote this.
    'single-quoted attr': `<img width="1080" height="2400" alt='x' src="${ATTACHMENT}">`,
    // Extra attributes would be discarded by a rewrite.
    'extra attr': `<img width="1080" height="2400" src="${ATTACHMENT}" title="mine">`,
    // Phantom attributes hidden inside a single-quoted value.
    'phantom attr': `<img width="1080" height="2400" title=' src="${ATTACHMENT}"' alt="x">`,
    'duplicate attr': `<img width="1080" width="1080" height="2400" src="${ATTACHMENT}">`,
    'valueless attr': `<img width="1080" height="2400" hidden src="${ATTACHMENT}">`,
    'unquoted value': `<img width=1080 height="2400" src="${ATTACHMENT}">`,
    'zero width': `<img width="0" height="2400" src="${ATTACHMENT}">`,
    'oversized width': `<img width="123456" height="240000" src="${ATTACHMENT}">`,
    'non-numeric width': `<img width="1080px" height="2400" src="${ATTACHMENT}">`,
    // "\b" would match this, because "-" is a word boundary in JS.
    'other element': `<img-card width="1080" height="2400" src="${ATTACHMENT}">`,
  }
  for (const [name, body] of Object.entries(cases)) {
    assert.deepStrictEqual(await rewrite(body, noProbe), { changed: false, body }, name)
  }
})

test('rewrite finds the tag end past a ">" inside a quoted value', async () => {
  const body = `<img width="1080" height="2400" alt="before > after" src="${ATTACHMENT}">`
  const result = await rewrite(body, noProbe)
  assert.strictEqual(result.changed, true)
  assert.strictEqual(
    result.body,
    `<a href="${ATTACHMENT}"><img src="${ATTACHMENT}" alt="before &gt; after" width="180"></a>`,
  )
})

test('rewrite respects backslash escaping of a tag', async () => {
  const escaped = `\\${uploaded(ATTACHMENT, 3000, 4000)}`
  assert.deepStrictEqual(await rewrite(escaped, noProbe), { changed: false, body: escaped })

  // An even run escapes the backslash, not the tag.
  const notEscaped = `\\\\${uploaded(ATTACHMENT, 3000, 4000)}`
  const result = await rewrite(notEscaped, noProbe)
  assert.strictEqual(result.changed, true)
  assert.ok(result.body.startsWith('\\\\<a href='), result.body)
})

test('rewrite ignores images inside HTML comments', async () => {
  const sameLine = `<!-- ${uploaded(ATTACHMENT, 3000, 4000)} -->`
  assert.deepStrictEqual(await rewrite(sameLine, noProbe), { changed: false, body: sameLine })

  const multiLine = ['<!--', uploaded(ATTACHMENT, 3000, 4000), `![a](${ATTACHMENT2})`, '-->'].join('\n')
  assert.deepStrictEqual(await rewrite(multiLine, tallProbe), { changed: false, body: multiLine })
})

test('rewrite leaves a tag wrapped in a Markdown link alone', async () => {
  const body = `[${uploaded(ATTACHMENT, 3000, 4000)}](https://example.com/details)`
  assert.deepStrictEqual(await rewrite(body, noProbe), { changed: false, body })
})

test('rewrite leaves a tag inside a multi-line anchor alone', async () => {
  const body = [
    '<a href="https://example.com/details">',
    uploaded(ATTACHMENT, 3000, 4000),
    '</a>',
  ].join('\n')
  assert.deepStrictEqual(await rewrite(body, noProbe), { changed: false, body })
})

test('rewrite leaves a tag linked to a relative or fragment target alone', async () => {
  // A link target needs no scheme. Missing one of these would nest an anchor
  // inside the author's own link.
  for (const target of ['#details', '/owner/repo/issues/1']) {
    const body = `[${uploaded(ATTACHMENT, 3000, 4000)}](${target})`
    assert.deepStrictEqual(await rewrite(body, noProbe), { changed: false, body }, target)
  }
})

test('rewrite leaves a tag inside an anchor opened at end of line alone', async () => {
  // A valid opener: the attributes continue on the next line.
  const body = [
    '<a',
    ' href="https://example.com/details">',
    uploaded(ATTACHMENT, 3000, 4000),
    '</a>',
  ].join('\n')
  assert.deepStrictEqual(await rewrite(body, noProbe), { changed: false, body })
})

test('an unclosed anchor inside a fence does not suppress later images', async () => {
  const body = [
    '```html',
    '<a href="https://example.com/details">',
    '```',
    '',
    uploaded(ATTACHMENT, 3000, 4000),
  ].join('\n')
  const result = await rewrite(body, noProbe)
  assert.strictEqual(result.changed, true)
  assert.ok(result.body.includes(`<a href="${ATTACHMENT}"><img `), result.body)
  assert.ok(result.body.includes('```html'), 'the fenced sample must be untouched')
})

test('a comment opener inside a fence does not suppress later images', async () => {
  const body = [
    '```html',
    '<!-- commented out',
    '```',
    '',
    uploaded(ATTACHMENT, 3000, 4000),
    '',
    `![shot](${ATTACHMENT2})`,
  ].join('\n')
  const result = await rewrite(body, tallProbe)
  assert.strictEqual(result.changed, true)
  assert.ok(result.body.includes(`<a href="${ATTACHMENT}"><img `), result.body)
  assert.ok(result.body.includes(`<a href="${ATTACHMENT2}"><img `), result.body)
})

test('a closing anchor inside inline code does not end the anchor', async () => {
  const body = [
    '<a href="https://example.com/details">',
    'as in `</a>`, which is text',
    uploaded(ATTACHMENT, 3000, 4000),
    '</a>',
  ].join('\n')
  assert.deepStrictEqual(await rewrite(body, noProbe), { changed: false, body })
})

test('an anchor inside a comment does not count as an open link', async () => {
  const body = ['<!-- <a href="/old"> -->', '', uploaded(ATTACHMENT, 3000, 4000)].join('\n')
  const result = await rewrite(body, noProbe)
  assert.strictEqual(result.changed, true)
  assert.ok(result.body.includes(`<a href="${ATTACHMENT}"><img `), result.body)
})

test('a comment still closes on a line that looks like code', async () => {
  // Markdown is not interpreted inside a comment, so the indented closer counts
  // even though an opener on that line would have been ignored.
  const body = ['<!--', '', '    -->', '', uploaded(ATTACHMENT, 3000, 4000)].join('\n')
  const result = await rewrite(body, noProbe)
  assert.strictEqual(result.changed, true)
  assert.ok(result.body.includes(`<a href="${ATTACHMENT}"><img `), result.body)
})

test('the probe budget covers Markdown images only', async () => {
  const probed = []
  const counting = {
    maxImages: 2,
    probe: async (url) => {
      probed.push(url)
      return { width: 1080, height: 2400 }
    },
  }
  const body = [
    `![a](${attachment(1)})`,
    `![b](${attachment(2)})`,
    `![c](${attachment(3)})`,
    uploaded(attachment(4), 3000, 4000),
    uploaded(attachment(5), 3000, 4000),
  ].join('\n\n')

  const result = await rewrite(body, counting)
  assert.strictEqual(result.changed, true)
  // The cap applies to the probed syntax only; tags make no requests.
  assert.deepStrictEqual(probed, [attachment(1), attachment(2)])
  assert.ok(result.body.includes(`![c](${attachment(3)})`), 'the capped image stays untouched')
  for (const n of [4, 5]) {
    assert.ok(result.body.includes(`<a href="${attachment(n)}"><img `), `tag ${n} should be rewritten`)
  }
})

test('rewrite stays fast on adversarial bodies', async () => {
  const cases = {
    // Unbounded alt/URL quantifiers made every "!" rescan to end-of-string.
    'unclosed image opens': '!['.repeat(32000),
    'nested brackets': '![' + '['.repeat(60000) + ']( https://x',
    'all backticks': '`'.repeat(65000),
    // The killer for /(`+)(.*?)\1/g: one long run, then a long non-backtick
    // tail. Took ~118 seconds before inlineCodeRanges became a linear scan.
    'backtick run then tail': '`'.repeat(30000) + 'x'.repeat(35000),
    'alternating backticks': '`x'.repeat(32000),
    'many fences': '```\n'.repeat(16000),
    'deep indent': '    x\n'.repeat(10000),
    // None of these terminate, so the tag scanner must give up per candidate
    // rather than rescan the rest of the line each time.
    'many img opens': '<img '.repeat(13000),
    'one endless attribute': `<img alt="${'x'.repeat(60000)}" src="x" width="1" height="2">`,
    'unterminated quotes': '<img alt="> '.repeat(5000),
  }
  for (const [name, body] of Object.entries(cases)) {
    const started = process.hrtime.bigint()
    await rewrite(body.slice(0, 65536))
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6
    assert.ok(elapsedMs < 1000, `${name} took ${elapsedMs.toFixed(0)}ms`)
  }
})

test('allowedUrl rejects non-default ports', () => {
  // hostname excludes the port, so this needs its own check.
  assert.strictEqual(allowedUrl('https://github.com:8443/user-attachments/assets/x'), null)
  assert.strictEqual(allowedUrl('https://user-images.githubusercontent.com:1337/a.png'), null)
})

test('codeLineIndices handles blockquoted and mid-content fences', () => {
  const lines = [
    '> ```kotlin',
    '> val x = 1',
    '> ```',
    'prose',
    '```',
    'still code, because "```foo" does not close a fence',
    '```foo',
    'also still code',
    '```',
    'free again',
  ]
  const marked = codeLineIndices(lines)
  assert.deepStrictEqual([...marked].sort((a, b) => a - b), [0, 1, 2, 4, 5, 6, 7, 8])
})

test('rewrite ignores images in blockquoted code fences', async () => {
  const body = ['> ```md', `> ![shot](${ATTACHMENT})`, '> ```'].join('\n')
  assert.deepStrictEqual(await rewrite(body), { changed: false, body })
})

test('rewrite leaves empty and oversized bodies alone', async () => {
  assert.deepStrictEqual(await rewrite(''), { changed: false, body: '' })
  assert.deepStrictEqual(await rewrite(undefined), { changed: false, body: '' })

  const huge = 'x'.repeat(65537)
  assert.deepStrictEqual(await rewrite(huge), { changed: false, body: huge })
})
