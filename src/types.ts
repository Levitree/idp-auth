import type { JWTPayload } from 'jose'

/** Who is calling, as proven by an idp.terranova.inc access token. */
export interface Principal {
  kind: 'user' | 'machine'
  /** Stable id for audit rows: `user:<sub>` or `m2m:<client_id>`. */
  id: string
  sub: string
  email?: string
  emailVerified: boolean
  /** Role names, system role first. For display and the few legacy readers; do not authorize on it. */
  roles: string[]
  /** Group names; homebase scopes organizations by them. */
  groups: string[]
  /** Sorted effective permission ids. The thing to check. */
  permissions: string[]
  /** Device UUIDs the subject is scoped to. Absent when the subject sees every device. */
  devices?: string[]
  /** Site ids the subject is scoped to. Absent when not scoped by site. */
  sites?: string[]
  /** Machine tokens: the integration's client id (= sub). */
  clientId?: string
  aud: string[]
  exp: number
  iat: number
  jti?: string
  /** Every verified claim, for anything not modelled above. */
  raw: JWTPayload
}

export type IdpAuthErrorCode =
  | 'TOKEN_MISSING'
  | 'TOKEN_INVALID'
  | 'AUDIENCE_REJECTED'
  | 'EMAIL_NOT_VERIFIED'
  | 'PERMISSIONS_MISSING'
  | 'FORBIDDEN'
  | 'DISCOVERY_FAILED'

export class IdpAuthError extends Error {
  readonly status: 401 | 403
  readonly code: IdpAuthErrorCode
  /** Set on FORBIDDEN: the permission ids that were required. */
  readonly permissions?: string[]

  constructor(message: string, status: 401 | 403, code: IdpAuthErrorCode, permissions?: string[]) {
    super(message)
    this.name = 'IdpAuthError'
    this.status = status
    this.code = code
    if (permissions) this.permissions = permissions
  }
}
