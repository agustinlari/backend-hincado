import { Hono } from 'hono'
import { sign } from 'hono/jwt'
import * as jose from 'jose'

// Cache para las claves públicas de Keycloak
let keycloakJWKS: jose.JSONWebKeySet | null = null
let jwksLastFetched = 0
const JWKS_CACHE_DURATION = 300000 // 5 minutos

async function getKeycloakJWKS(): Promise<jose.JSONWebKeySet> {
  const now = Date.now()

  if (keycloakJWKS && (now - jwksLastFetched) < JWKS_CACHE_DURATION) {
    return keycloakJWKS
  }

  try {
    const keycloakUrl = process.env.KEYCLOAK_INTERNAL_URL || 'http://127.0.0.1:8080'
    const realm = process.env.KEYCLOAK_REALM || 'master'
    const certsUrl = `${keycloakUrl}/auth/realms/${realm}/protocol/openid-connect/certs`

    console.log('🔐 Obteniendo JWKS de:', certsUrl)

    const response = await fetch(certsUrl)

    if (!response.ok) {
      throw new Error(`Error obteniendo JWKS: ${response.status} ${response.statusText}`)
    }

    keycloakJWKS = await response.json()
    jwksLastFetched = now

    console.log('✅ JWKS obtenido correctamente')
    return keycloakJWKS as jose.JSONWebKeySet

  } catch (error) {
    console.error('❌ Error obteniendo JWKS:', error)
    throw new Error('No se pudieron obtener las claves de Keycloak')
  }
}

async function validateKeycloakToken(token: string): Promise<any> {
  try {
    console.log('🔐 Validando token...')

    const jwks = await getKeycloakJWKS()
    const localJWKS = jose.createLocalJWKSet(jwks)

    const { payload } = await jose.jwtVerify(token, localJWKS, {
      issuer: undefined,
      audience: undefined,
    })

    console.log('✅ Token validado correctamente')
    console.log('🔐 Usuario:', payload.preferred_username || payload.sub)

    return payload

  } catch (error: any) {
    console.error('❌ Error validando token:', error.message)
    throw new Error('Token inválido')
  }
}

export function createAuthRouter(jwtSecret: string) {
  const router = new Hono()

  // Login endpoint
  router.post('/api/auth/login', async (c) => {
    try {
      const { username, password } = await c.req.json()

      if (!username || !password) {
        return c.json({ error: 'Username and password are required' }, 400)
      }

      const keycloakUrl = process.env.KEYCLOAK_INTERNAL_URL || 'http://127.0.0.1:8080'
      const realm = process.env.KEYCLOAK_REALM || 'master'
      const clientId = process.env.KEYCLOAK_CLIENT_ID || 'fotovoltaica-client'

      console.log('🔐 Iniciando login para:', username)
      console.log('🔗 URL interna:', keycloakUrl)
      console.log('🆔 Client ID:', clientId)

      // Obtener token de Keycloak usando URL interna
      const tokenUrl = `${keycloakUrl}/auth/realms/${realm}/protocol/openid-connect/token`
      const requestBody = new URLSearchParams({
        grant_type: 'password',
        client_id: clientId,
        username: username,
        password: password,
      })

      console.log('📡 URL completa:', tokenUrl)

      const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: requestBody,
      })

      console.log('📡 Status de respuesta:', response.status)

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        console.error('❌ Error de Keycloak:', errorData)
        return c.json({
          error: errorData.error_description || 'Credenciales inválidas'
        }, 401)
      }

      const tokenData = await response.json()

      // Validar y decodificar el token
      const keycloakUser = await validateKeycloakToken(tokenData.access_token)

      return c.json({
        success: true,
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token,
        expires_in: tokenData.expires_in,
        user: {
          sub: keycloakUser.sub,
          email: keycloakUser.email,
          name: keycloakUser.name || keycloakUser.preferred_username,
          preferred_username: keycloakUser.preferred_username
        }
      })

    } catch (error: any) {
      console.error('❌ Error completo:', error)
      return c.json({
        error: error.message || 'Error de autenticación'
      }, 401)
    }
  })

  // Callback endpoint
  router.get('/api/auth/callback', async (c) => {
    const code = c.req.query('code')

    if (!code) {
      return c.json({ error: 'Authorization code not provided' }, 400)
    }

    try {
      const keycloakUrl = process.env.KEYCLOAK_BASE_URL || 'https://aplicaciones.osmos.es:4444'
      const realm = process.env.KEYCLOAK_REALM || 'master'
      const clientId = process.env.KEYCLOAK_CLIENT_ID || 'fotovoltaica-client'
      const redirectUri = `${c.req.url.split('/api')[0]}/api/auth/callback`

      // Exchange code for tokens
      const tokenResponse = await fetch(`${keycloakUrl}/auth/realms/${realm}/protocol/openid-connect/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: clientId,
          code,
          redirect_uri: redirectUri
        })
      })

      if (!tokenResponse.ok) {
        throw new Error('Failed to exchange code for tokens')
      }

      const tokens = await tokenResponse.json()

      // Get user info
      const userInfoResponse = await fetch(`${keycloakUrl}/auth/realms/${realm}/protocol/openid-connect/userinfo`, {
        headers: {
          'Authorization': `Bearer ${tokens.access_token}`
        }
      })

      if (!userInfoResponse.ok) {
        throw new Error('Failed to get user info')
      }

      const userInfo = await userInfoResponse.json()

      // Create our own JWT token with user info
      const payload = {
        sub: userInfo.sub,
        email: userInfo.email,
        name: userInfo.name,
        preferred_username: userInfo.preferred_username,
        exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
      }

      const token = await sign(payload, jwtSecret)

      // Redirect to frontend with token
      return c.redirect(`/?token=${token}`)

    } catch (error) {
      console.error('Auth callback error:', error)
      return c.json({ error: 'Authentication failed' }, 500)
    }
  })

  // Verify token endpoint
  router.post('/api/auth/verify', async (c) => {
    const authHeader = c.req.header('Authorization')

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'No token provided' }, 401)
    }

    const token = authHeader.slice(7)

    try {
      // Validar token directamente con Keycloak
      const keycloakUser = await validateKeycloakToken(token)

      return c.json({
        user: {
          sub: keycloakUser.sub,
          email: keycloakUser.email,
          name: keycloakUser.name || keycloakUser.preferred_username,
          preferred_username: keycloakUser.preferred_username
        },
        valid: true
      })
    } catch (error: any) {
      console.error('Token verification failed:', error.message)
      return c.json({ error: 'Invalid token', valid: false }, 401)
    }
  })

  // Logout endpoint
  router.post('/api/auth/logout', (c) => {
    const keycloakUrl = process.env.KEYCLOAK_BASE_URL || 'https://aplicaciones.osmos.es:4444'
    const realm = process.env.KEYCLOAK_REALM || 'master'

    // Get the current origin to redirect back to login
    const host = c.req.header('host') || 'aplicaciones.osmos.es:4444'
    const protocol = host.includes('localhost') ? 'http' : 'https'

    console.log(`🔧 DEBUG - host: ${host}`)
    console.log(`🔧 DEBUG - keycloakUrl from env: ${process.env.KEYCLOAK_BASE_URL}`)
    console.log(`🔧 DEBUG - keycloakUrl final: ${keycloakUrl}`)

    // Construct the correct redirect URI for the login page
    let redirectUri
    if (host.includes('localhost')) {
      // Development environment - redirect to local app
      redirectUri = `${protocol}://${host}/`
    } else {
      // Production environment - redirect back to the fvhincado app
      // Try with just the base URL in case the client allows wildcards
      redirectUri = 'https://aplicaciones.osmos.es:4444/fvhincado'

      console.log(`🔧 DEBUG - Redirect URI: ${redirectUri}`)
    }

    // Fix: Keycloak is served under /auth/ according to nginx config
    const logoutUrl = `${keycloakUrl}/auth/realms/${realm}/protocol/openid-connect/logout?redirect_uri=${encodeURIComponent(redirectUri)}`

    console.log(`🚪 Logout URL generada: ${logoutUrl}`)
    console.log(`🔄 Redirect URI: ${redirectUri}`)

    return c.json({ logoutUrl })
  })

  return router
}

// Export validateKeycloakToken for use in auth middleware
export { validateKeycloakToken }
