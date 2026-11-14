import { describe, expect, it } from 'vitest'
import {
  canAccessDevice,
  createIdpVerifier,
  deviceScope,
  IdpAuthError,
  parseAudience,
  siteScope,
  verifyIdpToken,
} from '../src/index'
import { makeKeys, sign, userToken } from './helpers'

const keys = await makeKeys()
const verifier = createIdpVerifier({ audience: 'int_app, int_other', getKey: keys.getKey })

async function fails(promise: Promise<unknown>, code: string, status?: number) {
  const err = await promise.then(
    () => null,
    (e: unknown) => e
  )
  expect(err).toBeInstanceOf(IdpAuthError)
  expect((err as IdpAuthError).code).toBe(code)
  if (status) expect((err as IdpAuthError).status).toBe(status)
}

describe('parseAudience', () => {
  it('splits comma lists and trims', () => {
    expect(parseAudience('a, b ,,c')).toEqual(['a', 'b', 'c'])
    expect(parseAudience(['x'])).toEqual(['x'])
    expect(parseAudience(undefined)).toEqual([])
  })
})

describe('createIdpVerifier', () => {
  it('refuses to run without an audience', () => {
    expect(() => createIdpVerifier({ audience: '', getKey: keys.getKey })).toThrow(/audience/)
  })

  it('verifies a user token into a principal', async () => {
    const p = await verifier.verify(
      await userToken(keys.privateKey, {
        roles: ['employee', 'plc-author'],
        groups: ['aws-access'],
        permissions: ['fleet.devices.read_all', 'homebase.projects.write'],
      })
    )
    expect(p.kind).toBe('user')
    expect(p.id).toBe('user:user-1')
    expect(p.email).toBe('jake@terranova.inc')
    expect(p.emailVerified).toBe(true)
    expect(p.roles).toEqual(['employee', 'plc-author'])
    expect(p.groups).toEqual(['aws-access'])
    expect(p.permissions).toEqual(['fleet.devices.read_all', 'homebase.projects.write'])
    expect(p.devices).toBeUndefined()
    expect(p.aud).toEqual(['int_app'])
    expect(p.jti).toBe('jti-1')
  })

  it('accepts any configured audience and rejects others', async () => {
    const ok = await verifier.verify(await userToken(keys.privateKey, { aud: 'int_other' }))
    expect(ok.aud).toEqual(['int_other'])
    await fails(
      verifier.verify(await userToken(keys.privateKey, { aud: 'int_stranger' })),
      'AUDIENCE_REJECTED',
      401
    )
  })

  it('rejects the wrong issuer, an expired token and a bad signature', async () => {
    await fails(
      verifier.verify(await userToken(keys.privateKey, { issuer: 'https://evil.example' })),
      'TOKEN_INVALID'
    )
    await fails(verifier.verify(await userToken(keys.privateKey, { exp: '-1m' })), 'TOKEN_INVALID')
    const other = await makeKeys()
    await fails(verifier.verify(await userToken(other.privateKey)), 'TOKEN_INVALID')
  })

  it('rejects users without a verified email', async () => {
    await fails(
      verifier.verify(await userToken(keys.privateKey, { email_verified: false })),
      'EMAIL_NOT_VERIFIED',
      403
    )
    const relaxed = createIdpVerifier({
      audience: 'int_app',
      getKey: keys.getKey,
      requireEmailVerified: false,
    })
    const p = await relaxed.verify(await userToken(keys.privateKey, { email_verified: false }))
    expect(p.emailVerified).toBe(false)
  })

  it('rejects tokens that predate the permissions claim unless told otherwise', async () => {
    await fails(
      verifier.verify(await userToken(keys.privateKey, { permissions: undefined })),
      'PERMISSIONS_MISSING'
    )
    const legacy = createIdpVerifier({
      audience: 'int_app',
      getKey: keys.getKey,
      requirePermissionsClaim: false,
    })
    const p = await legacy.verify(await userToken(keys.privateKey, { permissions: undefined }))
    expect(p.permissions).toEqual([])
  })

  it('recognises machine tokens by gty and by aud = sub', async () => {
    const byGty = await verifier.verify(
      await sign(keys.privateKey, {
        sub: 'int_app',
        aud: 'int_app',
        gty: 'client_credentials',
        roles: ['employee'],
        permissions: ['sec.device.enrol'],
      })
    )
    expect(byGty.kind).toBe('machine')
    expect(byGty.id).toBe('m2m:int_app')
    expect(byGty.clientId).toBe('int_app')
    expect(byGty.emailVerified).toBe(false)
    expect(byGty.permissions).toEqual(['sec.device.enrol'])

    const legacy = await verifier.verify(
      await sign(keys.privateKey, { sub: 'int_app', aud: 'int_app', permissions: [] })
    )
    expect(legacy.kind).toBe('machine')

    // A machine token whose aud is not itself is malformed.
    await fails(
      verifier.verify(
        await sign(keys.privateKey, {
          sub: 'int_app',
          aud: 'int_other',
          gty: 'client_credentials',
          permissions: [],
        })
      ),
      'TOKEN_INVALID'
    )
  })

  it('carries device and site scope through', async () => {
    const p = await verifier.verify(
      await userToken(keys.privateKey, {
        permissions: ['fleet.devices.read'],
        devices: ['d1', 'd2'],
        sites: ['pine-ridge'],
      })
    )
    expect(p.devices).toEqual(['d1', 'd2'])
    expect(p.sites).toEqual(['pine-ridge'])
    expect(deviceScope(p)).toEqual(new Set(['d1', 'd2']))
    expect(canAccessDevice(p, 'd1')).toBe(true)
    expect(canAccessDevice(p, 'd9')).toBe(false)
    expect(siteScope(p)).toEqual(new Set(['pine-ridge']))
  })

  it('treats fleet.devices.read_all and site:* as unscoped', async () => {
    const p = await verifier.verify(
      await userToken(keys.privateKey, {
        permissions: ['fleet.devices.read_all'],
        devices: ['ignored'],
        sites: ['*'],
      })
    )
    expect(deviceScope(p)).toBeNull()
    expect(canAccessDevice(p, 'anything')).toBe(true)
    expect(siteScope(p)).toBeNull()
  })

  it('verifyIdpToken works without a prebuilt verifier', async () => {
    const p = await verifyIdpToken(await userToken(keys.privateKey), {
      audience: ['int_app'],
      getKey: keys.getKey,
    })
    expect(p.sub).toBe('user-1')
  })
})
