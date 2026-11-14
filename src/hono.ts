import type { Context, MiddlewareHandler, Next } from 'hono'
import {
  createIdpVerifier,
  hasAllPermissions,
  hasAnyPermission,
  type IdpVerifier,
  type VerifierOptions,
} from './index'
import { IdpAuthError, type Principal } from './types'

export type { Principal }

/** Add to your Hono env: `new Hono<{ Bindings: Env } & PrincipalVariables>()`. */
export interface PrincipalVariables {
  Variables: { principal: Principal }
}

export interface IdpAuthMiddlewareOptions {
  /**
   * Verifier options, or a function of the request context so audience and
   * issuer can come from `c.env` (Workers bindings are per request).
   */
  verifier: VerifierOptions | ((c: Context) => VerifierOptions)
  /** Shape the error response. Default: `{ error, code }` JSON with the status. */
  onError?: (c: Context, err: IdpAuthError) => Response | Promise<Response>
}

function defaultError(c: Context, err: IdpAuthError): Response {
  return c.json(
    {
      error: err.message,
      code: err.code,
      ...(err.permissions && { permissions: err.permissions }),
    },
    err.status
  )
}

const verifiers = new WeakMap<object, IdpVerifier>()

function verifierFor(c: Context, opts: IdpAuthMiddlewareOptions): IdpVerifier {
  if (typeof opts.verifier !== 'function') {
    let v = verifiers.get(opts)
    if (!v) {
      v = createIdpVerifier(opts.verifier)
      verifiers.set(opts, v)
    }
    return v
  }
  // Per-request options: cache on the env object, which Workers keep per isolate.
  const key = (c.env as object | undefined) ?? opts
  let v = verifiers.get(key)
  if (!v) {
    v = createIdpVerifier(opts.verifier(c))
    verifiers.set(key, v)
  }
  return v
}

/**
 * Authenticate the request with a Bearer idp.terranova.inc token and set
 * `c.var.principal`. 401 without a valid token, 403 for an unverified email.
 */
export function idpAuth(opts: IdpAuthMiddlewareOptions): MiddlewareHandler {
  const onError = opts.onError ?? defaultError
  return async (c: Context, next: Next) => {
    const header = c.req.header('Authorization')
    if (!header?.startsWith('Bearer ')) {
      return onError(c, new IdpAuthError('Missing bearer token', 401, 'TOKEN_MISSING'))
    }
    try {
      const principal = await verifierFor(c, opts).verify(header.slice(7))
      c.set('principal', principal)
    } catch (err) {
      if (err instanceof IdpAuthError) return onError(c, err)
      throw err
    }
    await next()
  }
}

/** The principal set by `idpAuth`. Throws if the middleware did not run. */
export function getPrincipal(c: Context): Principal {
  const p = c.get('principal') as Principal | undefined
  if (!p) throw new Error('@terranovasystems/idp-auth: idpAuth middleware has not run')
  return p
}

function forbidden(c: Context, onError: IdpAuthMiddlewareOptions['onError'], ids: string[]) {
  const err = new IdpAuthError(`Missing permission: ${ids.join(', ')}`, 403, 'FORBIDDEN', ids)
  return (onError ?? defaultError)(c, err)
}

/** 403 unless the principal holds every listed permission. Runs after `idpAuth`. */
export function requirePermission(...ids: string[]): MiddlewareHandler & {
  withErrorHandler: (h: IdpAuthMiddlewareOptions['onError']) => MiddlewareHandler
} {
  const make = (onError?: IdpAuthMiddlewareOptions['onError']): MiddlewareHandler => {
    return async (c: Context, next: Next) => {
      const p = getPrincipal(c)
      if (!hasAllPermissions(p, ids)) {
        return forbidden(
          c,
          onError,
          ids.filter((id) => !p.permissions.includes(id))
        )
      }
      await next()
    }
  }
  const handler = make() as MiddlewareHandler & {
    withErrorHandler: (h: IdpAuthMiddlewareOptions['onError']) => MiddlewareHandler
  }
  handler.withErrorHandler = (h) => make(h)
  return handler
}

/** 403 unless the principal holds at least one of the listed permissions. */
export function requireAnyPermission(...ids: string[]): MiddlewareHandler {
  return async (c: Context, next: Next) => {
    const p = getPrincipal(c)
    if (!hasAnyPermission(p, ids)) return forbidden(c, undefined, ids)
    await next()
  }
}

export const requireAllPermissions = requirePermission
