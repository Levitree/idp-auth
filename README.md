# @terranovasystems/idp-auth

Verify access tokens from `idp.terranova.inc` and check permissions. One implementation for every
Terranova Worker, so the rules live in one place:

- ES256 only, issuer pinned, keys from OIDC discovery (cached per isolate).
- `audience` is required. A service lists the OAuth client ids whose tokens it accepts
  (`OIDC_AUDIENCE`, comma-separated). No pin means the verifier refuses to start.
- Users need `email_verified`; machines (`gty: client_credentials`) do not.
- Tokens must carry `permissions[]`. Authorization is `permissions.includes('service.resource.action')`
  and nothing else. Role names are for display.
- Scope is separate from permission: `deviceScope()` and `siteScope()` read `devices[]` / `sites[]`.

The catalogue of permission ids is published at
`https://idp.terranova.inc/.well-known/permissions.json`.

## Hono

```ts
import { Hono } from 'hono'
import { idpAuth, requirePermission, getPrincipal, type PrincipalVariables } from '@terranovasystems/idp-auth/hono'
import { deviceScope } from '@terranovasystems/idp-auth'

const app = new Hono<{ Bindings: Env } & PrincipalVariables>()

app.use('/v1/*', idpAuth({ verifier: (c) => ({ audience: c.env.OIDC_AUDIENCE }) }))

app.post('/v1/projects', requirePermission('homebase.projects.write'), async (c) => {
  const p = getPrincipal(c) // { kind, id, sub, email, permissions, groups, devices?, ... }
  …
})

app.get('/v1/devices', async (c) => {
  const scope = deviceScope(getPrincipal(c)) // null = every device
  …
})
```

Errors are JSON `{ error, code, permissions? }` with status 401 or 403; pass `onError` to
`idpAuth`, or `requirePermission(...).withErrorHandler(fn)`, to match an existing error shape.

## Without Hono

```ts
import { verifyIdpToken } from '@terranovasystems/idp-auth'

const principal = await verifyIdpToken(token, { audience: env.OIDC_AUDIENCE })
```

## Release

Tag `vX.Y.Z` on `main`; the release workflow lints, tests, builds and publishes to npm with
`--access public`, like TerraUI.
