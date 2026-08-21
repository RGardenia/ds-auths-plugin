import { describe, expect, it } from 'vitest'
import { renderAuthPage } from '../src/auth-page.js'

describe('authentication page', () => {
  it('keeps hidden loading and setup elements out of layout', () => {
    const html = renderAuthPage('test-nonce')

    expect(html).toContain('[hidden]{display:none!important}')
  })
})
