import * as jose from 'jose'
import { IdpAuthError, type Principal } from './types.js'

export { IdpAuthError, type IdpAuthErrorCode, type Principal } from './types.js'

export const DEFAULT_ISSUER = 'https://idp.terranova.inc'

/** Lacking this permission means the token carries a `devices[]` scope. */
export const ALL_DEVICES_PERMISSION = 'fleet.devices.read_all'

/** The IdP signs every token with this algorithm; anything else is rejected. */
export const ALGORITHMS = ['ES256'] as const

export interface VerifierOptions {
  /**
   * Audience(s) this service accepts: the OAuth client ids whose tokens may
   * call it, as an array or a comma-separated string (the `OIDC_AUDIENCE`
   * convention). Required and non-empty: an unpinned verifier would accept a
   * token minted for any other service.
   */
  audience: string | readonly string[]
  /** Token issuer. Defaults to the production IdP. */
  issuer?: string
  /**
   * Where to fetch keys. Defaults to OIDC discovery under `issuer`. A
   * `JWTVerifyGetKey` (for tests, or a pre-built remote JWKS) skips discovery.
   */
  getKey?: jose.JWTVerifyGetKey
  /** Override `jwks_uri` without discovery. Ignored when `getKey` is given. */
  jwksUri?: string
  /** Users must have a verified email. Default true. Machines are exempt. */
  requireEmailVerified?: boolean
  /**
   * Tokens must carry `permissions[]`. Default true: a token without it
   * predates the permission model and nothing can be authorized on it.
   */
  requirePermissionsClaim?: boolean
  /** Fetch implementation for discovery (tests). */
  fetch?: typeof fetch
}

export interface IdpVerifier {
  verify(token: string): Promise<Principal>
  readonly issuer: string
  readonly audiences: readonly string[]
}

/** `OIDC_AUDIENCE="a,b, c"` → `['a', 'b', 'c']`. */
export function parseAudience(value: string | readonly string[] | undefined | null): string[] {
  if (!value) return []
  const list = typeof value === 'string' ? value.split(',') : value
  return list.map((s) => s.trim()).filter(Boolean)
}

interface Discovery {
  issuer: string
  jwks_uri: string
}

const discoveryCache = new Map<string, Promise<Discovery>>()
const jwksCache = new Map<string, jose.JWTVerifyGetKey>()

async function discover(issuer: string, fetchImpl: typeof fetch): Promise<Discovery> {
  const base = issuer.replace(/\/$/, '')
  let pending = discoveryCache.get(base)
  if (!pending) {
    pending = (async () => {
      const res = await fetchImpl(`${base}/.well-known/openid-configuration`, {
        headers: { Accept: 'application/json' },
      })
      if (!res.ok) {
        throw new IdpAuthError(`OIDC discovery failed: ${res.status}`, 401, 'DISCOVERY_FAILED')
      }
      return (await res.json()) as Discovery
    })().catch((err) => {
      discoveryCache.delete(base)
      throw err
    })
    discoveryCache.set(base, pending)
  }
  return pending
}

function remoteKeys(jwksUri: string): jose.JWTVerifyGetKey {
  let keys = jwksCache.get(jwksUri)
  if (!keys) {
    keys = jose.createRemoteJWKSet(new URL(jwksUri))
    jwksCache.set(jwksUri, keys)
  }
  return keys
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : []
}

/**
 * Machine tokens come from the `client_credentials` grant. The IdP marks them
 * with `gty`; older tokens are recognised by `aud` = `sub` = the client id,
 * which a user token can never satisfy.
 */
export function isMachinePayload(payload: jose.JWTPayload): boolean {
  if (payload.gty === 'client_credentials') return true
  const aud = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : []
  return aud.length === 1 && aud[0] === payload.sub
}

/** Build a verifier once per isolate and reuse it. */
export function createIdpVerifier(options: VerifierOptions): IdpVerifier {
  const issuer = (options.issuer ?? DEFAULT_ISSUER).replace(/\/$/, '')
  const audiences = parseAudience(options.audience)
  if (audiences.length === 0) {
    throw new Error(
      '@terranovasystems/idp-auth: audience is required. Set OIDC_AUDIENCE to the client ids this service accepts.'
    )
  }
  const requireEmailVerified = options.requireEmailVerified ?? true
  const requirePermissionsClaim = options.requirePermissionsClaim ?? true
  const fetchImpl = options.fetch ?? fetch

  async function keys(): Promise<{ getKey: jose.JWTVerifyGetKey; issuer: string }> {
    if (options.getKey) return { getKey: options.getKey, issuer }
    if (options.jwksUri) return { getKey: remoteKeys(options.jwksUri), issuer }
    const d = await discover(issuer, fetchImpl)
    return { getKey: remoteKeys(d.jwks_uri), issuer: d.issuer }
  }

  async function verify(token: string): Promise<Principal> {
    const k = await keys()
    let payload: jose.JWTPayload
    try {
      ;({ payload } = await jose.jwtVerify(token, k.getKey, {
        issuer: k.issuer,
        audience: audiences,
        algorithms: [...ALGORITHMS],
      }))
    } catch (err) {
      if (err instanceof jose.errors.JWTClaimValidationFailed && err.claim === 'aud') {
        throw new IdpAuthError('Token audience not accepted', 401, 'AUDIENCE_REJECTED')
      }
      throw new IdpAuthError('Invalid or expired token', 401, 'TOKEN_INVALID')
    }
    if (!payload.sub) throw new IdpAuthError('Token has no sub', 401, 'TOKEN_INVALID')

    const aud = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : []
    const machine = isMachinePayload(payload)
    const permissions = Array.isArray(payload.permissions) ? strings(payload.permissions) : null
    if (!permissions && requirePermissionsClaim) {
      throw new IdpAuthError(
        'Token carries no permissions claim; sign in again',
        401,
        'PERMISSIONS_MISSING'
      )
    }

    const base = {
      sub: payload.sub,
      roles: strings(payload.roles),
      groups: strings(payload.groups),
      permissions: permissions ?? [],
      aud,
      exp: payload.exp ?? 0,
      iat: payload.iat ?? 0,
      raw: payload,
      ...(typeof payload.jti === 'string' && { jti: payload.jti }),
    }

    if (machine) {
      if (!aud.includes(payload.sub)) {
        throw new IdpAuthError('Machine token audience mismatch', 401, 'TOKEN_INVALID')
      }
      return {
        kind: 'machine',
        id: `m2m:${payload.sub}`,
        emailVerified: false,
        clientId: payload.sub,
        ...base,
      }
    }

    const emailVerified = payload.email_verified === true
    if (requireEmailVerified && !emailVerified) {
      throw new IdpAuthError('Email not verified', 403, 'EMAIL_NOT_VERIFIED')
    }
    return {
      kind: 'user',
      id: `user:${payload.sub}`,
      emailVerified,
      ...(typeof payload.email === 'string' && { email: payload.email }),
      ...(Array.isArray(payload.devices) && { devices: strings(payload.devices) }),
      ...(Array.isArray(payload.sites) && { sites: strings(payload.sites) }),
      ...base,
    }
  }

  return { verify, issuer, audiences }
}

const verifierCache = new Map<string, IdpVerifier>()

/**
 * Verify a token with a cached verifier keyed by issuer + audience. Handy
 * outside Hono (WebSocket upgrades, queue consumers); the middleware uses it too.
 */
export function verifyIdpToken(token: string, options: VerifierOptions): Promise<Principal> {
  const key = `${options.issuer ?? DEFAULT_ISSUER}|${parseAudience(options.audience).join(',')}|${
    options.jwksUri ?? ''
  }`
  let v = options.getKey ? undefined : verifierCache.get(key)
  if (!v) {
    v = createIdpVerifier(options)
    if (!options.getKey) verifierCache.set(key, v)
  }
  return v.verify(token)
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

export function hasPermission(p: Pick<Principal, 'permissions'>, id: string): boolean {
  return p.permissions.includes(id)
}

export function hasAnyPermission(
  p: Pick<Principal, 'permissions'>,
  ids: readonly string[]
): boolean {
  return ids.some((id) => p.permissions.includes(id))
}

export function hasAllPermissions(
  p: Pick<Principal, 'permissions'>,
  ids: readonly string[]
): boolean {
  return ids.every((id) => p.permissions.includes(id))
}

/** Throws FORBIDDEN unless the principal holds every id. */
export function assertPermissions(p: Pick<Principal, 'permissions'>, ids: readonly string[]): void {
  const missing = ids.filter((id) => !p.permissions.includes(id))
  if (missing.length > 0) {
    throw new IdpAuthError(`Missing permission: ${missing.join(', ')}`, 403, 'FORBIDDEN', missing)
  }
}

/**
 * Which devices the principal may touch. `null` means every device (the
 * token holds `fleet.devices.read_all`); otherwise the set from `devices[]`,
 * possibly empty. Machines are unscoped unless the IdP says otherwise.
 */
export function deviceScope(p: Pick<Principal, 'permissions' | 'devices'>): Set<string> | null {
  if (p.permissions.includes(ALL_DEVICES_PERMISSION)) return null
  if (p.devices === undefined) return null
  return new Set(p.devices)
}

/** True when the principal may touch this device. */
export function canAccessDevice(
  p: Pick<Principal, 'permissions' | 'devices'>,
  deviceId: string
): boolean {
  const scope = deviceScope(p)
  return scope === null || scope.has(deviceId)
}

/** Which sites the principal may enter; `null` when not scoped by site. */
export function siteScope(p: Pick<Principal, 'sites'>): Set<string> | null {
  if (p.sites === undefined || p.sites.includes('*')) return null
  return new Set(p.sites)
}
