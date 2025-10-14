import { validateKeycloakToken } from '../routes/auth'

// Middleware for protected routes
export const createAuthMiddleware = () => {
  return async (c: any, next: any) => {
    console.log(`🔐 Auth middleware called for: ${c.req.method} ${c.req.url}`)

    // Skip auth in development mode if enabled
    if (process.env.ENABLE_DEV_AUTH === 'true') {
      c.set('user', { sub: '1', email: 'dev@example.com', name: 'Dev User' })
      return next()
    }

    const authHeader = c.req.header('Authorization')

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.error('❌ No authorization header found')
      return c.json({ error: 'Authentication required' }, 401)
    }

    const token = authHeader.slice(7)

    try {
      // Usar validateKeycloakToken en lugar de verify interno
      const keycloakUser = await validateKeycloakToken(token)
      c.set('user', {
        sub: keycloakUser.sub,
        email: keycloakUser.email,
        name: keycloakUser.name || keycloakUser.preferred_username,
        preferred_username: keycloakUser.preferred_username
      })

      console.log('✅ Token válido para usuario:', keycloakUser.preferred_username || keycloakUser.sub)
      return next()

    } catch (error: any) {
      console.error('❌ Token inválido:', error.message)
      return c.json({ error: 'Token inválido o expirado' }, 401)
    }
  }
}

// Export auth middleware for data exports (simplified version without full validation)
export const createExportAuthMiddleware = () => {
  return async (c: any, next: any) => {
    console.log(`📤 Export auth middleware called for: ${c.req.method} ${c.req.url}`)

    const authHeader = c.req.header('Authorization')

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.error('❌ No authorization header found')
      return c.json({ error: 'Authentication required for export' }, 401)
    }

    const token = authHeader.slice(7)

    try {
      const keycloakUser = await validateKeycloakToken(token)
      c.set('user', keycloakUser)
      return next()
    } catch (error: any) {
      console.error('❌ Export auth failed:', error.message)
      return c.json({ error: 'Export authentication failed' }, 401)
    }
  }
}
