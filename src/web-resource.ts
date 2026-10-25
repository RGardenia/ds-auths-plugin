import type { IncomingMessage, ServerResponse } from 'node:http'

/** Harness master resource routes also serve trusted in-process Peer reads. */
export type WebResource = (request: Request, peer?: object) => Promise<Response>

/** Forward a Fetch response with backpressure and cancellation on disconnect. */
export async function serveResource(request: IncomingMessage, response: ServerResponse, resource: WebResource): Promise<void> {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { allow: 'GET, HEAD' }).end()
    return
  }
  const headers = new Headers()
  for (const [name, value] of Object.entries(request.headers)) {
    for (const item of typeof value === 'string' ? [value] : value ?? []) headers.append(name, item)
  }
  const abort = new AbortController()
  let wake: (() => void) | undefined
  const onDrain = (): void => { wake?.(); wake = undefined }
  const onClose = (): void => { abort.abort(); onDrain() }
  response.on('close', onClose)
  response.on('drain', onDrain)
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined
  const cancel = (): void => { void reader?.cancel().catch(() => undefined) }
  abort.signal.addEventListener('abort', cancel)
  try {
    const result = await resource(new Request(new URL(request.url ?? '/', 'http://dsh.invalid'), {
      method: request.method, headers, signal: abort.signal,
    }))
    if (abort.signal.aborted) { await result.body?.cancel(); return }
    for (const [name, value] of result.headers) {
      if (name !== 'set-cookie') response.setHeader(name, value)
    }
    const cookies = result.headers.getSetCookie()
    if (cookies.length > 0) response.setHeader('set-cookie', cookies)
    response.writeHead(result.status)
    if (request.method === 'HEAD' || result.body === null) {
      await result.body?.cancel()
    } else {
      response.flushHeaders()
      reader = result.body.getReader()
      while (!abort.signal.aborted) {
        const chunk = await reader.read()
        if (chunk.done) break
        if (!response.write(chunk.value) && !abort.signal.aborted) await new Promise<void>(resolve => { wake = resolve })
      }
    }
    if (!abort.signal.aborted) response.end()
  } finally {
    if (reader !== undefined) {
      await reader.cancel().catch(() => undefined)
      reader.releaseLock()
    }
    abort.signal.removeEventListener('abort', cancel)
    response.off('close', onClose)
    response.off('drain', onDrain)
  }
}
