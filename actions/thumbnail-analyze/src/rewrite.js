'use strict'

// Rewrites oversized GitHub-hosted screenshots in issue/comment bodies into
// clickable thumbnails. Two syntaxes are covered: Markdown images, and the HTML
// `<img …>` tags GitHub's own uploader emits. The HTML form carries its
// dimensions inline, so only the Markdown form costs a network probe.
//
// This module runs in the unprivileged half of the thumbnail-images workflow:
// it touches attacker-controlled text and fetches attacker-supplied URLs, but
// the job it runs in holds no write scopes. It performs no GitHub API calls and
// returns plain data.

const probe = require('probe-image-size')

// Caller-tunable behaviour. Everything here is a presentation choice; the
// security bounds below are deliberately not configurable.
const DEFAULTS = {
  // Skip a body entirely when it carries this marker.
  optOut: '<!-- no-thumbnail -->',
  // GitHub caps issue/comment bodies at 65536 characters.
  maxBody: 65536,
  // Bounds the probe fan-out so one comment cannot stall the job or turn the
  // workflow into a request amplifier.
  maxImages: 20,
  probeTimeoutMs: 5000,
  // Only portrait images taller than this are touched. Landscape shots are
  // already constrained by the width of the comment column.
  minHeight: 640,
  // Rendered height we aim for; the emitted width is derived from it.
  targetHeight: 400,
  minWidth: 80,
}

// Exact host allowlist. Every entry is GitHub-controlled, so the redirect chain
// a probe follows is GitHub-controlled too. Repo content (raw.githubusercontent)
// is deliberately absent: those are not user uploads.
const ALLOWED_HOSTS = [
  { host: 'github.com', prefix: '/user-attachments/assets/' },
  { host: 'user-images.githubusercontent.com', prefix: '/' },
  { host: 'private-user-images.githubusercontent.com', prefix: '/' },
]

// Deliberately strict: no parentheses, quotes or whitespace in the URL, so a
// Markdown link containing parens cannot be mis-sliced. No nesting.
// Both runs are explicitly bounded: with an open-ended `[^\]]*` a body of
// "![![![..." makes every "!" rescan to end-of-string, which is quadratic.
const MAX_ALT = 300
const MAX_URL = 2048
const IMAGE_RE = new RegExp(
  `!\\[([^\\]]{0,${MAX_ALT}})\\]\\((https://[^\\s()<>"'\`]{1,${MAX_URL}})\\)`,
  'g',
)

// Bounds for the HTML tag scanner. A tag longer than this is not something the
// uploader produced, and giving up rather than scanning on keeps a line built
// from "<img " repeats linear instead of quadratic.
const MAX_TAG = 3500
const MAX_ATTR_NAME = 32
const MAX_ATTR_VALUE = MAX_URL

// The uploader emits exactly these attributes, always double-quoted. Anything
// beyond this grammar means a human wrote or edited the tag; their markup is
// left alone rather than re-emitted with the extra attributes silently dropped.
const IMG_ATTRS = new Set(['src', 'width', 'height', 'alt'])
const IMG_ATTRS_REQUIRED = ['src', 'width', 'height']

// Anchors and Markdown inline links wrapping an image. Both runs are bounded
// for the same reason IMAGE_RE is.
// The opener also ends at end of line: attributes may sit on the next line, and
// missing that opener would wrap an image that is already inside a link. Each
// line is matched separately, so "$" is that line's end.
const ANCHOR_RE = /<a(?=$|[\t\f\r />])|<\/a\s*>/gi
// The destination carries no scheme requirement: "#details" and "/owner/repo"
// link just as well as an absolute URL, and a link that goes unrecognised here
// gets an anchor nested inside the author's own.
const LINKED_RE = new RegExp(
  `\\[[^\\]]{0,${MAX_ALT}}\\]\\(([^\\s()<>"'\`]{0,${MAX_URL}})\\)`,
  'g',
)

/**
 * Validates a URL against the host allowlist.
 * @returns {string|null} the normalised URL, or null if it is not eligible.
 */
function allowedUrl(raw) {
  let url
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  if (url.protocol !== 'https:') return null
  // Credentials in the URL would make the runner send basic auth upstream.
  if (url.username || url.password) return null
  // hostname excludes the port, so this has to be checked separately.
  if (url.port !== '') return null

  const rule = ALLOWED_HOSTS.find((entry) => entry.host === url.hostname)
  if (!rule) return null
  // URL parsing already resolved any "..", so this cannot be walked out of.
  if (!url.pathname.startsWith(rule.prefix)) return null

  return url.toString()
}

function escapeAttr(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

// Attribute values read out of an existing tag are HTML-encoded, so they have
// to be decoded before they mean anything: an encoded "&" in a query string is
// part of the URL rather than markup, and alt text that is not decoded before
// escapeAttr() runs gains an escape level on every pass. "&amp;" is decoded
// last, so "&amp;lt;" yields the text "&lt;" instead of "<".
function unescapeAttr(value) {
  return String(value)
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&')
}

// Whitespace that separates attributes inside a tag.
function isTagSpace(ch) {
  return ch === ' ' || ch === '\t' || ch === '\f' || ch === '\r' || ch === '\n'
}

function isNameChar(ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '-'
}

/**
 * Parses the attribute list of an `<img` tag, starting right after the name.
 *
 * Hand-rolled rather than a regex: a pattern that terminates on the first ">"
 * mangles `alt="before > after"` into a half-tag, and one that models quoting
 * cannot be kept free of nested quantifiers. This is a single bounded pass.
 *
 * @returns {{end: number, attrs: Map<string,string>, strict: boolean}|null}
 *   null when the tag does not terminate within the bound, in which case the
 *   "<" is not a tag at all. `strict` is false once anything outside the
 *   uploader grammar is seen; the caller still needs `end` in that case.
 */
function parseImgAttrs(line, from) {
  const limit = Math.min(line.length, from + MAX_TAG)
  const attrs = new Map()
  let strict = true
  let i = from

  while (i < limit) {
    const ch = line[i]
    if (isTagSpace(ch)) {
      i++
      continue
    }
    if (ch === '>') return { end: i + 1, attrs, strict }
    if (ch === '/' && line[i + 1] === '>') return { end: i + 2, attrs, strict }

    let nameEnd = i
    while (nameEnd < limit && nameEnd - i < MAX_ATTR_NAME && isNameChar(line[nameEnd])) nameEnd++
    if (nameEnd === i) {
      // Not an attribute name. A quoted run still has to be stepped over as a
      // unit, or a ">" inside it would read as the end of the tag.
      if (ch === '"' || ch === "'") {
        const close = line.indexOf(ch, i + 1)
        if (close === -1 || close >= limit) return null
        i = close + 1
      } else {
        i++
      }
      strict = false
      continue
    }
    // HTML attribute names are case-insensitive, so a duplicate spelled in
    // another case still has to register as a duplicate.
    const name = line.slice(i, nameEnd).toLowerCase()
    i = nameEnd

    // The uploader writes name="value" with no spaces around the "=".
    if (line[i] !== '=') {
      strict = false
      continue
    }
    i++

    const quote = line[i]
    if (quote !== '"') {
      strict = false
      if (quote === "'") {
        // Single quotes hide phantom attributes: title=' src="…"'. Skipping the
        // whole run means the inner text is never read as attributes.
        const close = line.indexOf("'", i + 1)
        if (close === -1 || close >= limit) return null
        i = close + 1
      } else {
        while (i < limit && !isTagSpace(line[i]) && line[i] !== '>') i++
      }
      continue
    }
    const close = line.indexOf('"', i + 1)
    if (close === -1 || close >= limit) return null
    const value = line.slice(i + 1, close)
    if (value.length > MAX_ATTR_VALUE) strict = false
    if (attrs.has(name)) strict = false
    else attrs.set(name, value)
    i = close + 1
  }
  return null
}

function eligibleAttrs(parsed) {
  if (!parsed.strict) return null
  for (const name of parsed.attrs.keys()) {
    if (!IMG_ATTRS.has(name)) return null
  }
  for (const name of IMG_ATTRS_REQUIRED) {
    if (!parsed.attrs.has(name)) return null
  }
  return parsed.attrs
}

/**
 * Every `<img …>` tag on a line, in source order.
 *
 * Tags outside the uploader grammar are reported too, with attrs null: they are
 * not rewritten, but their extent is what keeps a Markdown image sitting inside
 * one of their attribute values from being rewritten in place.
 *
 * @returns {Array<{start: number, end: number, attrs: Map<string,string>|null}>}
 */
function htmlImgTags(line) {
  const tags = []
  let i = 0
  while (i < line.length) {
    const at = line.indexOf('<', i)
    if (at === -1) break
    i = at + 1
    if (line.slice(at + 1, at + 4).toLowerCase() !== 'img') continue

    const next = line[at + 4]
    // "<img-card>" must not match. A "\b" would match it, because "-" counts as
    // a word boundary in JS.
    if (next === undefined || !(isTagSpace(next) || next === '/' || next === '>')) continue

    // An odd number of backslashes makes this a GFM escaped literal, which
    // renders as text and must stay text.
    let slashes = 0
    while (at - slashes > 0 && line[at - slashes - 1] === '\\') slashes++
    if (slashes % 2 === 1) continue

    // Without a ">" in reach the tag cannot terminate. The lookahead is sliced
    // rather than searched to end-of-line, so a line of unterminated "<img "
    // repeats costs a bounded scan per repeat instead of a full one.
    if (line.slice(at, at + MAX_TAG + 1).indexOf('>') === -1) continue

    const parsed = parseImgAttrs(line, at + 4)
    if (!parsed) continue
    tags.push({ start: at, end: parsed.end, attrs: eligibleAttrs(parsed) })
    i = parsed.end
  }
  return tags
}

/**
 * Dimensions declared on a tag. Unlike the probe these are author-editable, so
 * only pure digit runs are accepted here and thumbnailWidth's bounds decide
 * whether the pair is worth acting on.
 */
function attrSize(attrs) {
  const width = unescapeAttr(attrs.get('width'))
  const height = unescapeAttr(attrs.get('height'))
  if (!/^\d{1,5}$/.test(width) || !/^\d{1,5}$/.test(height)) return null
  return { width: Number(width), height: Number(height) }
}

/**
 * Character ranges covered by HTML comments, per line. Comments span lines, so
 * the open state is carried forward the same way the fence state is in
 * codeLineIndices. Commented-out markup does not render and must not be
 * rewritten into something that does.
 *
 * The open state is cross-line, so an opener that never renders must not enter
 * it: a "<!--" shown as a code sample would otherwise silently suppress every
 * image below it for the rest of the body. Once a comment is genuinely open the
 * masks stop applying — inside a comment nothing is Markdown any more, so a
 * "-->" on an indented or fenced-looking line still closes it.
 *
 * @param {Set<number>} skipLines line indices sitting inside code blocks.
 * @param {Array<Array<[number, number]>>} inlineRangesPerLine inline code spans.
 */
function htmlCommentRanges(lines, skipLines, inlineRangesPerLine) {
  const perLine = []
  let open = false
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]
    const masked = skipLines.has(index)
    const inlineRanges = inlineRangesPerLine[index]
    const ranges = []
    let i = 0
    while (i < line.length) {
      if (open) {
        const close = line.indexOf('-->', i)
        if (close === -1) {
          ranges.push([i, line.length])
          break
        }
        ranges.push([i, close + 3])
        open = false
        i = close + 3
        continue
      }
      const start = line.indexOf('<!--', i)
      if (start === -1) break
      if (masked || inSpan(inlineRanges, start)) {
        // "<!--" has no self-overlap, so the whole token can be stepped over.
        i = start + 4
        continue
      }
      open = true
      i = start
    }
    perLine.push(ranges)
  }
  return perLine
}

/**
 * Character ranges covered by an open <a> element, per line, with the nesting
 * depth carried across lines so a wrapper split over several lines still
 * counts. A best-effort approximation rather than a parser: it answers only
 * "is this image already inside a link?", where a false positive costs a
 * missed thumbnail and a false negative would nest anchors.
 *
 * Tokens that do not render are ignored unconditionally, unlike the comment
 * tracker above: an "</a>" in a code sample is literal text even while an
 * anchor is open elsewhere, so acting on it would end the wrapper early and
 * expose the image it covers. A depth carried in from an earlier line still
 * covers these lines whole — the anchor around them is real either way.
 *
 * @param {Set<number>} skipLines line indices sitting inside code blocks.
 * @param {Array<Array<[number, number]>>} commentSpans ranges from htmlCommentRanges.
 * @param {Array<Array<[number, number]>>} inlineRangesPerLine inline code spans.
 */
function anchorRanges(lines, skipLines, commentSpans, inlineRangesPerLine) {
  const perLine = []
  let depth = 0
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]
    const ranges = []
    let openedAt = depth > 0 ? 0 : -1
    if (!skipLines.has(index)) {
      const inlineRanges = inlineRangesPerLine[index]
      const commentRanges = commentSpans[index]
      ANCHOR_RE.lastIndex = 0
      let match
      while ((match = ANCHOR_RE.exec(line)) !== null) {
        if (inSpan(inlineRanges, match.index) || inSpan(commentRanges, match.index)) continue
        if (match[0][1] === '/') {
          if (depth === 0) continue
          depth--
          if (depth === 0 && openedAt !== -1) {
            ranges.push([openedAt, match.index + match[0].length])
            openedAt = -1
          }
        } else {
          if (depth === 0) openedAt = match.index
          depth++
        }
      }
    }
    if (depth > 0 && openedAt !== -1) ranges.push([openedAt, line.length])
    perLine.push(ranges)
  }
  return perLine
}

/**
 * Spans of Markdown inline links on a line. An img inside "[<img …>](target)"
 * is the author's linked image: rewriting it would nest anchors and drop the
 * link target.
 */
function markdownLinkRanges(line) {
  const ranges = []
  LINKED_RE.lastIndex = 0
  let match
  while ((match = LINKED_RE.exec(line)) !== null) {
    ranges.push([match.index, match.index + match[0].length])
  }
  return ranges
}

function inSpan(ranges, at) {
  return ranges.some(([from, to]) => at >= from && at < to)
}

/**
 * Indices of lines that sit inside fenced or indented code blocks.
 */
function codeLineIndices(lines) {
  const inCode = new Set()
  let fence = null
  let indented = false
  let prevBlank = true

  for (let i = 0; i < lines.length; i++) {
    // Strip container prefixes so a fence is still recognised inside a
    // blockquote ("> ```") or a list item ("- ```"). Missing the opener is the
    // damaging direction: the fenced sample then gets rewritten as if it were
    // prose, and its closing fence reads as a stray opener that hides real
    // images further down.
    const line = lines[i]
      .replace(/^(?:\s*>)+ ?/, '')
      .replace(/^ {0,3}(?:[-*+]|\d{1,9}[.)]) +/, '')
    const fenceMatch = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line)

    if (fence) {
      inCode.add(i)
      // GFM only closes a fence when nothing but whitespace follows the run;
      // treating "```foo" as a close would end the block early and expose the
      // rest of it to rewriting.
      const closes =
        fenceMatch &&
        fenceMatch[1][0] === fence[0] &&
        fenceMatch[1].length >= fence.length &&
        fenceMatch[2].trim() === ''
      if (closes) fence = null
      continue
    }
    if (fenceMatch) {
      fence = fenceMatch[1]
      inCode.add(i)
      prevBlank = false
      indented = false
      continue
    }
    if (line.trim() === '') {
      // A blank line does not close an indented block.
      prevBlank = true
      continue
    }
    if (/^(?: {4}|\t)/.test(line) && (prevBlank || indented)) {
      inCode.add(i)
      indented = true
      prevBlank = false
      continue
    }
    indented = false
    prevBlank = false
  }
  return inCode
}

/**
 * Character ranges covered by inline code spans on a single line.
 *
 * Deliberately a hand-rolled scan rather than /(`+)(.*?)\1/g: on a line shaped
 * like 30k backticks followed by 35k other characters, that pattern backtracks
 * for around two minutes. This is a single linear pass. It approximates
 * CommonMark rather than implementing it, which is enough to answer the only
 * question asked of it: is this image inside inline code?
 */
function inlineCodeRanges(line) {
  const ranges = []
  const openers = new Map() // backtick run length -> index of the pending opener

  let i = 0
  while (i < line.length) {
    if (line[i] !== '`') {
      i++
      continue
    }
    let end = i
    while (end < line.length && line[end] === '`') end++
    const length = end - i

    if (openers.has(length)) {
      ranges.push([openers.get(length), end])
      openers.delete(length)
    } else {
      openers.set(length, i)
    }
    i = end
  }
  return ranges
}

async function probeSize(url, timeoutMs = DEFAULTS.probeTimeoutMs) {
  let timer
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve(null), timeoutMs)
    if (typeof timer.unref === 'function') timer.unref()
  })
  try {
    const result = await Promise.race([
      probe(url, {
        open_timeout: timeoutMs,
        response_timeout: timeoutMs,
        read_timeout: timeoutMs,
        follow_max: 3,
      }),
      timeout,
    ])
    if (!result) return null
    // Trust boundary with the image parser. The bytes behind an attachment URL
    // are fully attacker-controlled, so only two numbers are allowed out of
    // here; everything else the parser reports is discarded. Math.round() would
    // coerce a rogue string to NaN rather than let markup through, but NaN
    // passes every comparison below, so reject it explicitly.
    if (!Number.isFinite(result.width) || !Number.isFinite(result.height)) return null
    if (result.width <= 0 || result.height <= 0) return null
    return { width: result.width, height: result.height }
  } catch {
    // Broken, private, redirected or unsupported images are left untouched.
    return null
  } finally {
    clearTimeout(timer)
  }
}

/**
 * @returns {number|null} the width to render at, or null to leave the image alone.
 */
function thumbnailWidth(size, config = DEFAULTS) {
  if (!Number.isFinite(size.width) || !Number.isFinite(size.height)) return null
  if (size.width <= 0 || size.height <= 0) return null
  if (size.height <= size.width) return null
  if (size.height < config.minHeight) return null

  const width = Math.round(config.targetHeight * (size.width / size.height))
  // NaN would satisfy neither comparison, so assert the result directly.
  if (!Number.isFinite(width)) return null
  if (width < config.minWidth || width >= size.width) return null
  return width
}

// Only "width" is emitted. Setting "height" as well fights GitHub's
// max-width:100% and stretches the image on narrow displays.
function thumbnailHtml(url, alt, width) {
  const safeUrl = escapeAttr(url)
  return `<a href="${safeUrl}"><img src="${safeUrl}" alt="${escapeAttr(alt)}" width="${width}"></a>`
}

/**
 * @param {string} body Markdown body of an issue or comment.
 * @param {{probe?: (url: string) => Promise<{width: number, height: number}|null>}} [options]
 *   Seam for tests, so the replacement path can be covered without network access.
 * @returns {Promise<{changed: boolean, body: string}>}
 */
async function rewrite(body, { probe: probeFn, ...overrides } = {}) {
  const config = { ...DEFAULTS, ...overrides }
  const runProbe = probeFn || ((url) => probeSize(url, config.probeTimeoutMs))
  if (typeof body !== 'string' || body.length === 0) return { changed: false, body: '' }
  if (body.length > config.maxBody) return { changed: false, body }
  if (body.includes(config.optOut)) return { changed: false, body }

  const lines = body.split('\n')
  const skipLines = codeLineIndices(lines)
  // Computed up front rather than per hit line: the cross-line trackers need
  // the same spans to tell a rendered token from one that is only shown.
  const inlineRanges = lines.map((line) => inlineCodeRanges(line))
  const commentSpans = htmlCommentRanges(lines, skipLines, inlineRanges)
  const anchorSpans = anchorRanges(lines, skipLines, commentSpans, inlineRanges)

  const hits = []
  for (let i = 0; i < lines.length; i++) {
    if (skipLines.has(i)) continue
    const codeRanges = inlineRanges[i]
    const commentRanges = commentSpans[i]

    const tags = htmlImgTags(lines[i])
    const linkRanges = tags.length > 0 ? markdownLinkRanges(lines[i]) : []
    for (const tag of tags) {
      if (!tag.attrs) continue
      if (inSpan(codeRanges, tag.start)) continue
      if (inSpan(commentRanges, tag.start)) continue
      // Already inside a link, so it is already clickable; wrapping it again
      // would nest anchors.
      if (inSpan(anchorSpans[i], tag.start)) continue
      if (inSpan(linkRanges, tag.start)) continue

      const url = allowedUrl(unescapeAttr(tag.attrs.get('src')))
      if (!url) continue
      const size = attrSize(tag.attrs)
      if (!size) continue
      // The tag states its own dimensions, so this hit needs no probe.
      const width = thumbnailWidth(size, config)
      if (!width) continue

      hits.push({
        line: i,
        start: tag.start,
        end: tag.end,
        alt: unescapeAttr(tag.attrs.get('alt') || ''),
        url,
        width,
      })
    }

    IMAGE_RE.lastIndex = 0
    let match
    while ((match = IMAGE_RE.exec(lines[i])) !== null) {
      const start = match.index
      if (codeRanges.some(([from, to]) => start >= from && start < to)) continue
      if (inSpan(commentRanges, start)) continue
      // Inside an img tag's attribute value, e.g. alt="![a](url)". Rewriting
      // there would splice markup into the middle of the tag.
      if (tags.some((tag) => start >= tag.start && start < tag.end)) continue

      const prev = start > 0 ? lines[i][start - 1] : ''
      // "\![alt](url)" is an escaped literal, not an image.
      if (prev === '\\') continue
      // "[![alt](url)](target)" is a linked image. Rewriting the inner image
      // would strip the author's link target, and it is already clickable,
      // which is the whole point of the rewrite.
      if (prev === '[') continue

      const url = allowedUrl(match[2])
      if (!url) continue

      // No dimensions in the source, so this one has to be probed.
      hits.push({ line: i, start, end: start + match[0].length, alt: match[1], url, width: null })
    }
  }
  if (hits.length === 0) return { changed: false, body }

  hits.sort((a, b) => a.line - b.line || a.start - b.start)
  // Containment the other way round: "![… <img …> …](url)" puts a tag inside a
  // Markdown image's alt text. Keeping the outer, earlier-starting hit and
  // dropping whatever it swallows leaves exactly one rewrite per region.
  const merged = []
  for (const hit of hits) {
    const previous = merged[merged.length - 1]
    if (previous && previous.line === hit.line && hit.start < previous.end) continue
    merged.push(hit)
  }

  // The cap exists to bound outbound requests, so it counts distinct URLs
  // rather than occurrences. Counting occurrences would let twenty repeats of
  // one thumbnail-sized image crowd out a genuine screenshot further down.
  // Tags carry their dimensions inline and issue no requests, so they neither
  // consume the budget nor are limited by it.
  const probeUrls = merged.filter((hit) => hit.width === null).map((hit) => hit.url)
  const probeTargets = [...new Set(probeUrls)].slice(0, config.maxImages)
  const sizes = new Map()
  for (const url of probeTargets) {
    sizes.set(url, await runProbe(url))
  }

  // Apply right-to-left so earlier offsets stay valid.
  let changed = false
  for (const hit of merged.slice().reverse()) {
    let width = hit.width
    if (width === null) {
      const size = sizes.get(hit.url)
      if (!size) continue
      width = thumbnailWidth(size, config)
      if (!width) continue
    }

    const line = lines[hit.line]
    lines[hit.line] =
      line.slice(0, hit.start) + thumbnailHtml(hit.url, hit.alt, width) + line.slice(hit.end)
    changed = true
  }
  if (!changed) return { changed: false, body }

  const updated = lines.join('\n')
  // Refuse to produce a body GitHub would reject.
  if (updated.length > config.maxBody) return { changed: false, body }

  return { changed: true, body: updated }
}

module.exports = {
  rewrite,
  allowedUrl,
  thumbnailWidth,
  codeLineIndices,
  escapeAttr,
  unescapeAttr,
  DEFAULTS,
}
