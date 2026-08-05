'use strict'

// Entry point for the thumbnail-analyze action.
//
// This is the unprivileged half of the thumbnail workflow. It runs in a job
// that holds no token scopes at all, reads the event payload straight off disk
// rather than through workflow expressions, and emits plain data. It makes no
// GitHub API calls.

const crypto = require('crypto')
const fs = require('fs')
const zlib = require('zlib')
const { rewrite, DEFAULTS } = require('./rewrite')

// Base64 characters. Node's per-environment-string ceiling is ~128 KiB, and the
// consuming job receives this through `env:`. Stop short of the limit so an
// incompressible body is a clean no-op rather than a step that cannot start.
const MAX_ENCODED = 100000

function input(name, fallback) {
  const raw = process.env[`INPUT_${name.toUpperCase()}`]
  return raw === undefined || raw.trim() === '' ? fallback : raw
}

function numericInput(name, fallback) {
  const value = Number(input(name, fallback))
  return Number.isFinite(value) && value > 0 ? value : fallback
}

function setOutput(key, value) {
  // Every value written here is a boolean, a hex digest or base64, so none can
  // contain a newline and break out of the key=value form.
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`)
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex')
}

function bodyFromEvent(eventName, payload) {
  if (eventName === 'issue_comment') return payload.comment && payload.comment.body
  if (eventName === 'issues') return payload.issue && payload.issue.body
  return null
}

async function main() {
  const eventName = process.env.GITHUB_EVENT_NAME
  const payload = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'))

  const original = bodyFromEvent(eventName, payload)
  if (typeof original !== 'string') {
    console.log(`event=${eventName} carries no body to rewrite`)
    setOutput('changed', 'false')
    return
  }

  const config = {
    optOut: input('opt-out-marker', DEFAULTS.optOut),
    targetHeight: numericInput('target-height', DEFAULTS.targetHeight),
    minHeight: numericInput('min-height', DEFAULTS.minHeight),
    maxImages: numericInput('max-images', DEFAULTS.maxImages),
  }

  const result = await rewrite(original, config)

  if (!result.changed) {
    console.log(`event=${eventName} changed=false`)
    setOutput('changed', 'false')
    return
  }

  const packed = zlib.gzipSync(Buffer.from(result.body, 'utf8')).toString('base64')
  if (packed.length > MAX_ENCODED) {
    console.log(`skipping: encoded body is ${packed.length} chars, over the ${MAX_ENCODED} limit`)
    setOutput('changed', 'false')
    return
  }

  setOutput('changed', 'true')
  setOutput('body-gz-b64', packed)
  // The body analysed here is a snapshot from the webhook. Between now and the
  // API call the author may have edited it again, and blindly writing would
  // revert that edit. Hand the privileged job a fingerprint of what we analysed
  // so it can refuse to overwrite anything newer.
  setOutput('original-sha', sha256(original))

  console.log(`event=${eventName} changed=true encoded=${packed.length} chars`)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
