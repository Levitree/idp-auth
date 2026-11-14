import { Hono } from 'hono'
import { describe, expect, it } from 'vitest'
import { getPrincipal, idpAuth, requireAnyPermission, requirePermission } from '../src/hono'
import type { PrincipalVariables } from '../src/hono'
import { makeKeys, sign, userToken } from './helpers'

const keys = await makeKeys()

function app() {
  const a = new Hono<{ Bindings: { OIDC_AUDIENCE: string } } & PrincipalVariables>()
  a.use(
    '/v1/*',
    idpAuth({
      verifier: (c) => ({ audience: c.env.OIDC_AUDIENCE, getKey: keys.getKey }),
    })
  )
  a.get('/v1/me', (c) => c.json({ id: getPrincipal(c).id }))
  a.post('/v1/projects', requirePermission('homebase.projects.write'), (c) => c.json({ ok: true }))
  a.get('/v1/either', requireAnyPermission('a.b.c', 'homebase.projects.read'), (c) =>
    c.json({ ok: true })
  )
  a.get(
    '/v1/custom',
    requirePermission('x.y.z').withErrorHandler((c, err) => c.text(`nope: ${err.code}`, 403)),
    (c) => c.json({ ok: true })
  )
  return a
}

const env = { OIDC_AUDIENCE: 'int_app' }

async function call(path: string, token?: string, method = 'GET') {
  return app().request(
    path,
    { method, headers: token ? { Authorization: `Bearer ${token}` } : {} },
    env
  )
}

describe('idpAuth', () => {
  it('401s without a token', async () => {
    const res = await call('/v1/me')
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Missing bearer token', code: 'TOKEN_MISSING' })
  })

  it('sets the principal', async () => {
    const res = await call('/v1/me', await userToken(keys.privateKey))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ id: 'user:user-1' })
  })

  it('403s an unverified user', async () => {
    const res = await call('/v1/me', await userToken(keys.privateKey, { email_verified: false }))
    expect(res.status).toBe(403)
    expect(((await res.json()) as { code: string }).code).toBe('EMAIL_NOT_VERIFIED')
  })

  it('reads the audience from env', async () => {
    const res = await call('/v1/me', await userToken(keys.privateKey, { aud: 'int_other' }))
    expect(res.status).toBe(401)
  })
})

describe('requirePermission', () => {
  it('passes with the permission and 403s without, naming what is missing', async () => {
    const ok = await call(
      '/v1/projects',
      await userToken(keys.privateKey, { permissions: ['homebase.projects.write'] }),
      'POST'
    )
    expect(ok.status).toBe(200)

    const no = await call('/v1/projects', await userToken(keys.privateKey), 'POST')
    expect(no.status).toBe(403)
    expect(await no.json()).toEqual({
      error: 'Missing permission: homebase.projects.write',
      code: 'FORBIDDEN',
      permissions: ['homebase.projects.write'],
    })
  })

  it('applies to machines the same way', async () => {
    const token = await sign(keys.privateKey, {
      sub: 'int_app',
      aud: 'int_app',
      gty: 'client_credentials',
      permissions: ['homebase.projects.write'],
    })
    expect((await call('/v1/projects', token, 'POST')).status).toBe(200)
  })

  it('requireAnyPermission accepts one of several', async () => {
    expect((await call('/v1/either', await userToken(keys.privateKey))).status).toBe(200)
    expect(
      (await call('/v1/either', await userToken(keys.privateKey, { permissions: [] }))).status
    ).toBe(403)
  })

  it('supports a custom error handler', async () => {
    const res = await call('/v1/custom', await userToken(keys.privateKey))
    expect(res.status).toBe(403)
    expect(await res.text()).toBe('nope: FORBIDDEN')
  })
})
