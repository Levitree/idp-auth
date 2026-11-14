import * as jose from 'jose'

export const ISSUER = 'https://idp.terranova.inc'

export async function makeKeys() {
  const { privateKey, publicKey } = await jose.generateKeyPair('ES256', { extractable: true })
  const getKey: jose.JWTVerifyGetKey = async () => publicKey
  return { privateKey, publicKey, getKey }
}

export interface TokenInput {
  sub?: string
  aud?: string | string[]
  roles?: string[]
  groups?: string[]
  permissions?: string[] | undefined
  devices?: string[]
  sites?: string[]
  email?: string
  email_verified?: boolean
  gty?: string
  exp?: string
  alg?: string
  issuer?: string
}

export async function sign(privateKey: CryptoKey, input: TokenInput = {}): Promise<string> {
  const claims: Record<string, unknown> = {
    roles: input.roles ?? ['employee'],
    groups: input.groups ?? [],
  }
  if (input.permissions !== undefined) claims.permissions = input.permissions
  if (input.devices) claims.devices = input.devices
  if (input.sites) claims.sites = input.sites
  if (input.email) claims.email = input.email
  if (input.email_verified !== undefined) claims.email_verified = input.email_verified
  if (input.gty) claims.gty = input.gty
  return new jose.SignJWT(claims)
    .setProtectedHeader({ alg: input.alg ?? 'ES256', kid: 'test' })
    .setIssuedAt()
    .setIssuer(input.issuer ?? ISSUER)
    .setSubject(input.sub ?? 'user-1')
    .setAudience(input.aud ?? 'int_app')
    .setExpirationTime(input.exp ?? '5m')
    .setJti('jti-1')
    .sign(privateKey)
}

export function userToken(privateKey: CryptoKey, input: TokenInput = {}) {
  return sign(privateKey, {
    email: 'jake@terranova.inc',
    email_verified: true,
    permissions: ['fleet.devices.read', 'homebase.projects.read'],
    ...input,
  })
}
