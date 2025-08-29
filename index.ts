import 'dotenv/config'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { Pool } from 'pg'
import { serve } from '@hono/node-server'
import { jwt, sign, verify } from 'hono/jwt'
import * as jose from 'jose'

const app = new Hono()

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production'

// Configure CORS
app.use('/*', cors({
  origin: ['http://localhost:5173', 'http://localhost:3000', 'http://localhost:8789', 'https://aplicaciones.osmos.es:4444'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowHeaders: ['Content-Type', 'Authorization'],
}))

// Database connection
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'fvinspeccioneshincas',
  password: process.env.DB_PASSWORD || 'Osmos2017',
  port: parseInt(process.env.DB_PORT || '5432'),
})

app.get('/', (c) => c.text('¡Hola desde Hono backend!'))

// Cache para las claves públicas de Keycloak
let keycloakJWKS: jose.JSONWebKeySet | null = null;
let jwksLastFetched = 0;
const JWKS_CACHE_DURATION = 300000; // 5 minutos

async function getKeycloakJWKS(): Promise<jose.JSONWebKeySet> {
  const now = Date.now();
  
  if (keycloakJWKS && (now - jwksLastFetched) < JWKS_CACHE_DURATION) {
    return keycloakJWKS;
  }

  try {
    const keycloakUrl = process.env.KEYCLOAK_INTERNAL_URL || 'http://127.0.0.1:8080'
    const realm = process.env.KEYCLOAK_REALM || 'master'
    const certsUrl = `${keycloakUrl}/auth/realms/${realm}/protocol/openid-connect/certs`
    
    console.log('🔐 Obteniendo JWKS de:', certsUrl);
    
    const response = await fetch(certsUrl);
    
    if (!response.ok) {
      throw new Error(`Error obteniendo JWKS: ${response.status} ${response.statusText}`);
    }
    
    keycloakJWKS = await response.json();
    jwksLastFetched = now;
    
    console.log('✅ JWKS obtenido correctamente');
    return keycloakJWKS as jose.JSONWebKeySet;
    
  } catch (error) {
    console.error('❌ Error obteniendo JWKS:', error);
    throw new Error('No se pudieron obtener las claves de Keycloak');
  }
}

async function validateKeycloakToken(token: string): Promise<any> {
  try {
    console.log('🔐 Validando token...');
    
    const jwks = await getKeycloakJWKS();
    const localJWKS = jose.createLocalJWKSet(jwks);
    
    const { payload } = await jose.jwtVerify(token, localJWKS, {
      issuer: undefined,
      audience: undefined,
    });

    console.log('✅ Token validado correctamente');
    console.log('🔐 Usuario:', payload.preferred_username || payload.sub);
    
    return payload;
    
  } catch (error: any) {
    console.error('❌ Error validando token:', error.message);
    throw new Error('Token inválido');
  }
}

// Auth endpoints
app.post('/api/auth/login', async (c) => {
  try {
    const { username, password } = await c.req.json()
    
    if (!username || !password) {
      return c.json({ error: 'Username and password are required' }, 400)
    }

    const keycloakUrl = process.env.KEYCLOAK_INTERNAL_URL || 'http://127.0.0.1:8080'
    const realm = process.env.KEYCLOAK_REALM || 'master'
    const clientId = process.env.KEYCLOAK_CLIENT_ID || 'fotovoltaica-client'
    
    console.log('🔐 Iniciando login para:', username);
    console.log('🔗 URL interna:', keycloakUrl);
    console.log('🆔 Client ID:', clientId);
    
    // Obtener token de Keycloak usando URL interna
    const tokenUrl = `${keycloakUrl}/realms/${realm}/protocol/openid-connect/token`
    const requestBody = new URLSearchParams({
      grant_type: 'password',
      client_id: clientId,
      username: username,
      password: password,
    })

    console.log('📡 URL completa:', tokenUrl);

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: requestBody,
    });

    console.log('📡 Status de respuesta:', response.status);

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      console.error('❌ Error de Keycloak:', errorData);
      return c.json({ 
        error: errorData.error_description || 'Credenciales inválidas' 
      }, 401);
    }

    const tokenData = await response.json();

    // Validar y decodificar el token
    const keycloakUser = await validateKeycloakToken(tokenData.access_token);

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
    });

  } catch (error: any) {
    console.error('❌ Error completo:', error);
    return c.json({ 
      error: error.message || 'Error de autenticación' 
    }, 401);
  }
})

app.get('/api/auth/callback', async (c) => {
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
    const tokenResponse = await fetch(`${keycloakUrl}/realms/${realm}/protocol/openid-connect/token`, {
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
    const userInfoResponse = await fetch(`${keycloakUrl}/realms/${realm}/protocol/openid-connect/userinfo`, {
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
    
    const token = await sign(payload, JWT_SECRET)
    
    // Redirect to frontend with token
    return c.redirect(`/?token=${token}`)
    
  } catch (error) {
    console.error('Auth callback error:', error)
    return c.json({ error: 'Authentication failed' }, 500)
  }
})

app.post('/api/auth/verify', async (c) => {
  const authHeader = c.req.header('Authorization')
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'No token provided' }, 401)
  }
  
  const token = authHeader.slice(7)
  
  try {
    // Validar token directamente con Keycloak
    const keycloakUser = await validateKeycloakToken(token);
    
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
    console.error('Token verification failed:', error.message);
    return c.json({ error: 'Invalid token', valid: false }, 401)
  }
})

app.post('/api/auth/logout', (c) => {
  const keycloakUrl = process.env.KEYCLOAK_BASE_URL || 'https://aplicaciones.osmos.es:4444'
  const realm = process.env.KEYCLOAK_REALM || 'master'
  
  // Get the current origin to redirect back to login
  const host = c.req.header('host') || 'aplicaciones.osmos.es:4444'
  const protocol = host.includes('localhost') ? 'http' : 'https'
  
  console.log(`🔧 DEBUG - host: ${host}`);
  console.log(`🔧 DEBUG - keycloakUrl from env: ${process.env.KEYCLOAK_BASE_URL}`);
  console.log(`🔧 DEBUG - keycloakUrl final: ${keycloakUrl}`);
  
  // Construct the correct redirect URI for the login page
  let redirectUri;
  if (host.includes('localhost')) {
    // Development environment - redirect to local app
    redirectUri = `${protocol}://${host}/`
  } else {
    // Production environment - redirect back to the fvhincado app
    // Try with just the base URL in case the client allows wildcards
    redirectUri = 'https://aplicaciones.osmos.es:4444/fvhincado'
    
    console.log(`🔧 DEBUG - Redirect URI: ${redirectUri}`);
  }
  
  // Fix: Keycloak is served under /auth/ according to nginx config
  const logoutUrl = `${keycloakUrl}/auth/realms/${realm}/protocol/openid-connect/logout?redirect_uri=${encodeURIComponent(redirectUri)}`
  
  console.log(`🚪 Logout URL generada: ${logoutUrl}`);
  console.log(`🔄 Redirect URI: ${redirectUri}`);
  
  return c.json({ logoutUrl })
})

// Middleware for protected routes
const authMiddleware = async (c: any, next: any) => {
  console.log(`🔐 Auth middleware called for: ${c.req.method} ${c.req.url}`);
  
  // Skip auth in development mode if enabled
  if (process.env.ENABLE_DEV_AUTH === 'true') {
    c.set('user', { sub: '1', email: 'dev@example.com', name: 'Dev User' })
    return next()
  }
  
  const authHeader = c.req.header('Authorization')
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('❌ No authorization header found');
    return c.json({ error: 'Authentication required' }, 401)
  }
  
  const token = authHeader.slice(7)
  
  try {
    // Usar validateKeycloakToken en lugar de verify interno
    const keycloakUser = await validateKeycloakToken(token);
    c.set('user', {
      sub: keycloakUser.sub,
      email: keycloakUser.email,
      name: keycloakUser.name || keycloakUser.preferred_username,
      preferred_username: keycloakUser.preferred_username
    })
    console.log(`✅ Auth successful for: ${c.req.method} ${c.req.url}`);
    return next()
  } catch (error: any) {
    console.error(`❌ Auth failed for ${c.req.method} ${c.req.url}:`, error.message);
    return c.json({ error: 'Invalid token' }, 401)
  }
}

// Middleware para endpoints de exportación - soporta tanto Bearer token como API Key
const exportAuthMiddleware = async (c: any, next: any) => {
  console.log(`🔐 Export auth middleware called for: ${c.req.method} ${c.req.url}`);
  
  // Skip auth in development mode if enabled
  if (process.env.ENABLE_DEV_AUTH === 'true') {
    c.set('user', { sub: '1', email: 'dev@example.com', name: 'Dev User' })
    return next()
  }

  // Check for API Key first (for Power Query)
  const apiKey = c.req.header('x-api-key')
  if (apiKey) {
    const validApiKey = process.env.API_KEY || 'kE7pZ2nQ9xR4sWbV1yU8vA3mF6jH1gC4' // Default key para development
    if (apiKey === validApiKey) {
      c.set('user', { sub: 'api-key-user', email: 'api@system.com', name: 'API Key User' })
      console.log(`✅ API Key auth successful for: ${c.req.method} ${c.req.url}`);
      return next()
    } else {
      console.error('❌ Invalid API Key');
      return c.json({ error: 'Invalid API Key' }, 401)
    }
  }
  
  // Fallback to Bearer token authentication
  const authHeader = c.req.header('Authorization')
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('❌ No authorization header or API key found');
    return c.json({ error: 'Authentication required - provide Bearer token or x-api-key header' }, 401)
  }
  
  const token = authHeader.slice(7)
  
  try {
    const keycloakUser = await validateKeycloakToken(token);
    c.set('user', {
      sub: keycloakUser.sub,
      email: keycloakUser.email,
      name: keycloakUser.name || keycloakUser.preferred_username,
      preferred_username: keycloakUser.preferred_username
    })
    console.log(`✅ Bearer token auth successful for: ${c.req.method} ${c.req.url}`);
    return next()
  } catch (error: any) {
    console.error(`❌ Auth failed for ${c.req.method} ${c.req.url}:`, error.message);
    return c.json({ error: 'Invalid token' }, 401)
  }
}

// Get all mesas with their CT and plantilla info
app.get('/api/mesas', authMiddleware, async (c) => {
  try {
    const query = `
      SELECT 
        m.id_mesa,
        m.nombre_mesa,
        m.coord_x,
        m.coord_y,
        ct.nombre_ct,
        mp.nombre_plantilla,
        mp.dimension_x,
        mp.dimension_y
      FROM mesas m
      JOIN cts ct ON m.id_ct = ct.id_ct
      JOIN mesa_plantillas mp ON m.id_plantilla = mp.id_plantilla
      WHERE m.coord_x IS NOT NULL AND m.coord_y IS NOT NULL
      ORDER BY m.nombre_mesa
    `
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching mesas:', error)
    return c.json({ error: 'Failed to fetch mesas' }, 500)
  }
})

// Get mesa details by ID
app.get('/api/mesas/:id', authMiddleware, async (c) => {
  const id = c.req.param('id')
  try {
    const query = `
      SELECT 
        m.id_mesa,
        m.nombre_mesa,
        m.coord_x,
        m.coord_y,
        ct.nombre_ct,
        mp.nombre_plantilla,
        mp.descripcion as plantilla_descripcion,
        mp.dimension_x,
        mp.dimension_y
      FROM mesas m
      JOIN cts ct ON m.id_ct = ct.id_ct
      JOIN mesa_plantillas mp ON m.id_plantilla = mp.id_plantilla
      WHERE m.id_mesa = $1
    `
    const result = await pool.query(query, [id])
    
    if (result.rows.length === 0) {
      return c.json({ error: 'Mesa not found' }, 404)
    }
    
    return c.json(result.rows[0])
  } catch (error) {
    console.error('Error fetching mesa:', error)
    return c.json({ error: 'Failed to fetch mesa' }, 500)
  }
})

// Get components for a mesa
app.get('/api/mesas/:id/components', authMiddleware, async (c) => {
  const id = c.req.param('id')
  console.log(`🔍 GET /api/mesas/${id}/components called`)
  try {
    const query = `
      SELECT 
        pc.id_componente,
        pc.tipo_elemento,
        pc.coord_x,
        pc.coord_y,
        pc.descripcion_punto_montaje,
        pc.orden_prioridad
      FROM mesas m
      JOIN plantilla_componentes pc ON m.id_plantilla = pc.id_plantilla
      WHERE m.id_mesa = $1
      ORDER BY pc.orden_prioridad ASC, pc.tipo_elemento, pc.coord_x, pc.coord_y
    `
    const result = await pool.query(query, [id])
    console.log(`✅ Found ${result.rows.length} components for mesa ${id}`)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching mesa components:', error)
    return c.json({ error: 'Failed to fetch mesa components' }, 500)
  }
})

// Recalculate mesa dimensions based on components
app.post('/api/recalculate-dimensions', async (c) => {
  try {
    // Calculate dimensions for each plantilla based on component coordinates
    const updateQuery = `
      UPDATE mesa_plantillas 
      SET 
          dimension_x = GREATEST(
              COALESCE(
                  CASE 
                      WHEN componentes.num_paneles > 0 THEN
                          -- Component coords are in mm, add 1000mm (1m) margin for panels
                          (componentes.max_x - componentes.min_x) + 1000.0
                      ELSE
                          -- Add 400mm (0.4m) margin for mounting points
                          (componentes.max_x - componentes.min_x) + 400.0
                  END, 
                  20000.0  -- Default 20m in mm
              ), 
              1000.0  -- Minimum 1m in mm
          ),
          dimension_y = GREATEST(
              COALESCE(
                  CASE 
                      WHEN componentes.num_paneles > 0 THEN
                          -- Component coords are in mm, add 1000mm (1m) margin for panels
                          (componentes.max_y - componentes.min_y) + 1000.0
                      ELSE
                          -- Add 400mm (0.4m) margin for mounting points
                          (componentes.max_y - componentes.min_y) + 400.0
                  END, 
                  6000.0   -- Default 6m in mm
              ), 
              1000.0   -- Minimum 1m in mm
          )
      FROM (
          SELECT 
              id_plantilla,
              MAX(coord_x) as max_x,
              MIN(coord_x) as min_x,
              MAX(coord_y) as max_y,
              MIN(coord_y) as min_y,
              COUNT(CASE WHEN tipo_elemento = 'PANEL' THEN 1 END) as num_paneles
          FROM plantilla_componentes
          GROUP BY id_plantilla
      ) as componentes
      WHERE mesa_plantillas.id_plantilla = componentes.id_plantilla
    `;
    
    const result = await pool.query(updateQuery);
    
    // Set default dimensions for plantillas without components
    const defaultQuery = `
      UPDATE mesa_plantillas 
      SET 
          dimension_x = 20000.0,  -- 20m in mm
          dimension_y = 6000.0    -- 6m in mm
      WHERE id_plantilla NOT IN (
          SELECT DISTINCT id_plantilla 
          FROM plantilla_componentes
      )
    `;
    
    await pool.query(defaultQuery);
    
    // Get summary of changes
    const summaryQuery = `
      SELECT 
          mp.id_plantilla,
          mp.nombre_plantilla,
          ROUND((mp.dimension_x / 1000.0)::numeric, 2) as dimension_x_meters,
          ROUND((mp.dimension_y / 1000.0)::numeric, 2) as dimension_y_meters,
          COALESCE(comp_stats.total_componentes, 0) as total_componentes,
          COALESCE(comp_stats.num_paneles, 0) as num_paneles,
          COALESCE(comp_stats.num_puntos_montaje, 0) as num_puntos_montaje
      FROM mesa_plantillas mp
      LEFT JOIN (
          SELECT 
              id_plantilla,
              COUNT(*) as total_componentes,
              COUNT(CASE WHEN tipo_elemento = 'PANEL' THEN 1 END) as num_paneles,
              COUNT(CASE WHEN tipo_elemento = 'PUNTO_MONTAJE' THEN 1 END) as num_puntos_montaje
          FROM plantilla_componentes
          GROUP BY id_plantilla
      ) comp_stats ON mp.id_plantilla = comp_stats.id_plantilla
      ORDER BY mp.nombre_plantilla
    `;
    
    const summary = await pool.query(summaryQuery);
    
    return c.json({ 
      message: 'Dimensions recalculated successfully',
      updated_plantillas: result.rowCount,
      plantillas: summary.rows
    });
    
  } catch (error) {
    console.error('Error recalculating dimensions:', error);
    return c.json({ error: 'Failed to recalculate dimensions' }, 500);
  }
});

// ==================== TIPOS DE ENSAYO ====================

// Get all tipos de ensayo
app.get('/api/tipos-ensayo', authMiddleware, async (c) => {
  try {
    const query = `
      SELECT 
        id_tipo_ensayo,
        nombre_ensayo,
        descripcion,
        unidad_medida,
        grupo_ensayo,
        tipo_resultado,
        minimo_admisible,
        maximo_admisible,
        orden_prioridad
      FROM tipos_ensayo
      ORDER BY orden_prioridad ASC, grupo_ensayo, nombre_ensayo
    `
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching tipos de ensayo:', error)
    return c.json({ error: 'Failed to fetch tipos de ensayo' }, 500)
  }
})

// Create tipo de ensayo
app.post('/api/tipos-ensayo', authMiddleware, async (c) => {
  try {
    const body = await c.req.json()
    const { 
      nombre_ensayo, 
      descripcion, 
      unidad_medida, 
      grupo_ensayo, 
      tipo_resultado, 
      minimo_admisible, 
      maximo_admisible 
    } = body
    
    if (!nombre_ensayo || !tipo_resultado) {
      return c.json({ error: 'Missing required fields: nombre_ensayo, tipo_resultado' }, 400)
    }
    
    const query = `
      INSERT INTO tipos_ensayo (
        nombre_ensayo, descripcion, unidad_medida, grupo_ensayo, 
        tipo_resultado, minimo_admisible, maximo_admisible
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `
    
    const result = await pool.query(query, [
      nombre_ensayo, descripcion, unidad_medida, grupo_ensayo,
      tipo_resultado, minimo_admisible, maximo_admisible
    ])
    
    return c.json(result.rows[0])
  } catch (error) {
    console.error('Error creating tipo de ensayo:', error)
    return c.json({ error: 'Failed to create tipo de ensayo' }, 500)
  }
})

// ==================== REGLAS DE COLORES PARA RESULTADOS ====================

// Get all color rules for test results
app.get('/api/reglas-resultados-ensayos', authMiddleware, async (c) => {
  try {
    const query = `
      SELECT 
        r.id,
        r.id_tipo_ensayo,
        r.tipo_condicion,
        r.valor_numerico_1,
        r.valor_numerico_2,
        r.valor_booleano,
        r.valor_texto,
        r.resaltado,
        r.comentario,
        r.prioridad,
        te.nombre_ensayo,
        te.tipo_resultado
      FROM reglas_resultados_ensayos r
      JOIN tipos_ensayo te ON r.id_tipo_ensayo = te.id_tipo_ensayo
      ORDER BY r.id_tipo_ensayo, r.prioridad DESC, r.id
    `
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching color rules:', error)
    return c.json({ error: 'Failed to fetch color rules' }, 500)
  }
})

// Create color rule
app.post('/api/reglas-resultados-ensayos', authMiddleware, async (c) => {
  try {
    const body = await c.req.json()
    const { 
      id_tipo_ensayo,
      tipo_condicion,
      valor_numerico_1,
      valor_numerico_2,
      valor_booleano,
      valor_texto,
      resaltado,
      comentario,
      prioridad = 0
    } = body
    
    if (!id_tipo_ensayo || !tipo_condicion) {
      return c.json({ error: 'Missing required fields: id_tipo_ensayo, tipo_condicion' }, 400)
    }
    
    // Validate tipo_condicion
    const validConditions = ['=', '<>', '>', '<', '>=', '<=', 'ENTRE', 'FUERA_DE']
    if (!validConditions.includes(tipo_condicion)) {
      return c.json({ error: 'Invalid tipo_condicion. Must be one of: ' + validConditions.join(', ') }, 400)
    }
    
    const query = `
      INSERT INTO reglas_resultados_ensayos (
        id_tipo_ensayo, tipo_condicion, valor_numerico_1, valor_numerico_2,
        valor_booleano, valor_texto, resaltado, comentario, prioridad
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `
    
    const result = await pool.query(query, [
      id_tipo_ensayo, tipo_condicion, valor_numerico_1, valor_numerico_2,
      valor_booleano, valor_texto, resaltado, comentario, prioridad
    ])
    
    return c.json({
      success: true,
      regla: result.rows[0],
      message: 'Regla de color creada exitosamente'
    })
  } catch (error) {
    console.error('Error creating color rule:', error)
    return c.json({ error: 'Failed to create color rule' }, 500)
  }
})

// Update color rule
app.put('/api/reglas-resultados-ensayos/:id', authMiddleware, async (c) => {
  try {
    const id = c.req.param('id')
    const body = await c.req.json()
    const { 
      id_tipo_ensayo,
      tipo_condicion,
      valor_numerico_1,
      valor_numerico_2,
      valor_booleano,
      valor_texto,
      resaltado,
      comentario,
      prioridad
    } = body
    
    // Validate tipo_condicion if provided
    if (tipo_condicion) {
      const validConditions = ['=', '<>', '>', '<', '>=', '<=', 'ENTRE', 'FUERA_DE']
      if (!validConditions.includes(tipo_condicion)) {
        return c.json({ error: 'Invalid tipo_condicion. Must be one of: ' + validConditions.join(', ') }, 400)
      }
    }
    
    const query = `
      UPDATE reglas_resultados_ensayos 
      SET 
        id_tipo_ensayo = COALESCE($1, id_tipo_ensayo),
        tipo_condicion = COALESCE($2, tipo_condicion),
        valor_numerico_1 = COALESCE($3, valor_numerico_1),
        valor_numerico_2 = COALESCE($4, valor_numerico_2),
        valor_booleano = COALESCE($5, valor_booleano),
        valor_texto = COALESCE($6, valor_texto),
        resaltado = COALESCE($7, resaltado),
        comentario = COALESCE($8, comentario),
        prioridad = COALESCE($9, prioridad)
      WHERE id = $10
      RETURNING *
    `
    
    const result = await pool.query(query, [
      id_tipo_ensayo, tipo_condicion, valor_numerico_1, valor_numerico_2,
      valor_booleano, valor_texto, resaltado, comentario, prioridad, id
    ])
    
    if (result.rows.length === 0) {
      return c.json({ error: 'Color rule not found' }, 404)
    }
    
    return c.json({
      success: true,
      regla: result.rows[0],
      message: 'Regla de color actualizada exitosamente'
    })
  } catch (error) {
    console.error('Error updating color rule:', error)
    return c.json({ error: 'Failed to update color rule' }, 500)
  }
})

// Delete color rule
app.delete('/api/reglas-resultados-ensayos/:id', authMiddleware, async (c) => {
  try {
    const id = c.req.param('id')
    
    const query = `
      DELETE FROM reglas_resultados_ensayos 
      WHERE id = $1
      RETURNING id
    `
    
    const result = await pool.query(query, [id])
    
    if (result.rows.length === 0) {
      return c.json({ error: 'Color rule not found' }, 404)
    }
    
    return c.json({
      success: true,
      message: 'Regla de color eliminada exitosamente'
    })
  } catch (error) {
    console.error('Error deleting color rule:', error)
    return c.json({ error: 'Failed to delete color rule' }, 500)
  }
})

// ==================== INSPECCIONES ====================

// Create a new inspection session
app.post('/api/inspecciones', authMiddleware, async (c) => {
  try {
    const body = await c.req.json()
    const { descripcion } = body
    
    // Get user ID from auth token
    const user = c.get('user')
    
    // Extract user ID from the JWT token (sub field contains the user ID)
    // For now, we'll use a hash of the sub to create a consistent integer ID
    const id_usuario = user?.sub ? Math.abs(user.sub.split('').reduce((hash, char) => {
      return ((hash << 5) - hash + char.charCodeAt(0)) & 0xffffffff;
    }, 0)) : 1
    
    console.log('👤 Creando inspección para usuario:', { id_usuario, userSub: user?.sub, username: user?.preferred_username });
    
    // Store user info in cache for future lookups
    if (user?.sub) {
      storeUserInfo(user.sub, id_usuario, {
        name: user.name,
        preferred_username: user.preferred_username
      });
    }
    
    const query = `
      INSERT INTO inspecciones (id_usuario, descripcion, estado)
      VALUES ($1, $2, 'EN_PROCESO')
      RETURNING *
    `
    
    const result = await pool.query(query, [id_usuario, descripcion || null])
    
    return c.json({
      success: true,
      inspeccion: result.rows[0],
      message: 'Inspección creada exitosamente'
    })
  } catch (error) {
    console.error('Error creating inspection:', error)
    return c.json({ error: 'Failed to create inspection' }, 500)
  }
})

// Update inspection status
app.patch('/api/inspecciones/:id', authMiddleware, async (c) => {
  try {
    const id_inspeccion = c.req.param('id')
    const body = await c.req.json()
    const { estado, descripcion, fecha_fin } = body
    
    const query = `
      UPDATE inspecciones 
      SET 
        estado = COALESCE($1, estado),
        descripcion = COALESCE($2, descripcion),
        fecha_fin = COALESCE($3, fecha_fin)
      WHERE id_inspeccion = $4
      RETURNING *
    `
    
    const result = await pool.query(query, [estado, descripcion, fecha_fin, id_inspeccion])
    
    if (result.rows.length === 0) {
      return c.json({ error: 'Inspection not found' }, 404)
    }
    
    return c.json({
      success: true,
      inspeccion: result.rows[0],
      message: 'Inspección actualizada exitosamente'
    })
  } catch (error) {
    console.error('Error updating inspection:', error)
    return c.json({ error: 'Failed to update inspection' }, 500)
  }
})


// Get all inspections
app.get('/api/inspecciones', authMiddleware, async (c) => {
  try {
    const query = `
      SELECT 
        id_inspeccion,
        id_usuario,
        fecha_inicio,
        fecha_fin,
        descripcion,
        estado
      FROM inspecciones
      ORDER BY fecha_inicio DESC
    `
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching inspections:', error)
    return c.json({ error: 'Failed to fetch inspections' }, 500)
  }
})

// Test endpoint for DELETE method
app.delete('/api/test-delete/:id', async (c) => {
  return c.json({ success: true, message: 'DELETE test successful', id: c.req.param('id') })
})

// Delete inspection
app.delete('/api/inspecciones/:id', authMiddleware, async (c) => {
  console.log('🗑️ DELETE /api/inspecciones/:id called with id:', c.req.param('id'))
  try {
    const id_inspeccion = c.req.param('id')
    
    const query = `
      DELETE FROM inspecciones 
      WHERE id_inspeccion = $1
      RETURNING id_inspeccion
    `
    
    const result = await pool.query(query, [id_inspeccion])
    
    if (result.rows.length === 0) {
      return c.json({ error: 'Inspection not found' }, 404)
    }
    
    return c.json({
      success: true,
      message: 'Inspección eliminada exitosamente'
    })
  } catch (error) {
    console.error('Error deleting inspection:', error)
    return c.json({ error: 'Failed to delete inspection' }, 500)
  }
})

// User cache to store user information
// Maps both UUID (from JWT) and integer ID (from DB) to user info
const userCache = new Map<string, { name?: string, preferred_username?: string, userId?: number, uuid?: string }>();
const idToUuidCache = new Map<number, string>(); // Maps integer ID back to UUID

// Function to get or fetch user info by integer ID
async function getUserInfo(userId: string): Promise<{ name?: string, preferred_username?: string }> {
  const numericUserId = parseInt(userId);
  
  // First check if we have UUID mapping for this numeric ID
  const uuid = idToUuidCache.get(numericUserId);
  if (uuid && userCache.has(uuid)) {
    return userCache.get(uuid)!;
  }
  
  // Check cache by string ID directly
  if (userCache.has(userId)) {
    return userCache.get(userId)!;
  }
  
  // For now, return a placeholder. In a real implementation, you would:
  // 1. Query a local users table, or
  // 2. Make a call to Keycloak Admin API to get user info, or
  // 3. Store user info when they first authenticate
  const userInfo = { name: `Usuario ${userId}`, preferred_username: `user${userId}` };
  userCache.set(userId, userInfo);
  return userInfo;
}

// Function to store user info and create mappings
function storeUserInfo(uuid: string, userId: number, userInfo: { name?: string, preferred_username?: string }) {
  // Store in cache with UUID as key
  userCache.set(uuid, { ...userInfo, userId, uuid });
  // Create reverse mapping from integer ID to UUID
  idToUuidCache.set(userId, uuid);
}

// Get all inspections (simplified for now - later filter by mesa through resultados_ensayos)
app.get('/api/mesas/:id/inspecciones', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    
    // Get query parameters for filtering
    const showAll = c.req.query('showAll') === 'true';
    const filterByUser = c.req.query('filterByUser') !== 'false'; // Default to true
    const filterByStatus = c.req.query('filterByStatus') !== 'false'; // Default to true
    
    // Store current user info in cache if available
    let currentUserId = 1;
    if (user?.sub) {
      currentUserId = Math.abs(user.sub.split('').reduce((hash, char) => {
        return ((hash << 5) - hash + char.charCodeAt(0)) & 0xffffffff;
      }, 0));
      
      storeUserInfo(user.sub, currentUserId, {
        name: user.name,
        preferred_username: user.preferred_username
      });
    }
    
    // Build query with conditional WHERE clause
    let query = `
      SELECT 
        id_inspeccion,
        fecha_inicio,
        fecha_fin,
        descripcion,
        estado,
        id_usuario
      FROM inspecciones
    `;
    
    const conditions = [];
    const params = [];
    let paramIndex = 1;
    
    // Apply filters if not showing all
    if (!showAll) {
      if (filterByUser) {
        conditions.push(`id_usuario = $${paramIndex}`);
        params.push(currentUserId);
        paramIndex++;
      }
      
      if (filterByStatus) {
        conditions.push(`estado = $${paramIndex}`);
        params.push('EN_PROCESO');
        paramIndex++;
      }
    }
    
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }
    
    query += ` ORDER BY fecha_inicio DESC`;
    
    console.log('🔍 Query inspecciones:', { query, params, showAll, currentUserId, userSub: user?.sub });
    
    const result = await pool.query(query, params)
    
    // Enrich inspections with user information
    const enrichedInspections = await Promise.all(result.rows.map(async (inspection) => {
      const userInfo = await getUserInfo(inspection.id_usuario.toString());
      return {
        ...inspection,
        usuario_nombre: userInfo.name,
        usuario_username: userInfo.preferred_username
      };
    }));
    
    return c.json(enrichedInspections)
  } catch (error) {
    console.error('Error fetching inspections:', error)
    return c.json({ error: 'Failed to fetch inspections' }, 500)
  }
})

// ==================== RESULTADOS DE ENSAYOS ====================

// Create resultado de ensayo
app.post('/api/resultados-ensayos', authMiddleware, async (c) => {
  try {
    const body = await c.req.json()
    const { 
      id_inspeccion, 
      id_tipo_ensayo, 
      id_mesa, 
      id_componente_plantilla_1, 
      id_componente_plantilla_2,
      resultado_numerico,
      resultado_booleano,
      resultado_texto,
      comentario
    } = body
    
    // Validate required fields
    if (!id_inspeccion || !id_tipo_ensayo || !id_mesa || !id_componente_plantilla_1) {
      return c.json({ 
        error: 'Missing required fields: id_inspeccion, id_tipo_ensayo, id_mesa, id_componente_plantilla_1' 
      }, 400)
    }
    
    const query = `
      INSERT INTO resultados_ensayos (
        id_inspeccion, id_tipo_ensayo, id_mesa, 
        id_componente_plantilla_1, id_componente_plantilla_2,
        resultado_numerico, resultado_booleano, resultado_texto, comentario
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `
    
    const result = await pool.query(query, [
      id_inspeccion, id_tipo_ensayo, id_mesa,
      id_componente_plantilla_1, id_componente_plantilla_2,
      resultado_numerico, resultado_booleano, resultado_texto, comentario
    ])
    
    return c.json({
      success: true,
      resultado: result.rows[0],
      message: 'Resultado de ensayo guardado exitosamente'
    })
  } catch (error) {
    console.error('Error creating resultado ensayo:', error)
    return c.json({ error: 'Failed to create resultado ensayo' }, 500)
  }
})

// Get all components with mesa information
app.get('/api/components', authMiddleware, async (c) => {
  try {
    const query = `
      SELECT 
        pc.id_componente,
        pc.id_plantilla,
        pc.tipo_elemento,
        pc.coord_x,
        pc.coord_y,
        pc.descripcion_punto_montaje,
        mp.nombre_plantilla,
        mp.descripcion as plantilla_descripcion,
        mp.dimension_x as plantilla_dimension_x,
        mp.dimension_y as plantilla_dimension_y,
        m.id_mesa,
        m.nombre_mesa,
        m.coord_x as mesa_coord_x,
        m.coord_y as mesa_coord_y,
        ct.nombre_ct
      FROM plantilla_componentes pc
      JOIN mesa_plantillas mp ON pc.id_plantilla = mp.id_plantilla
      JOIN mesas m ON m.id_plantilla = mp.id_plantilla
      JOIN cts ct ON m.id_ct = ct.id_ct
      WHERE pc.tipo_elemento = 'PUNTO_MONTAJE'
      ORDER BY ct.nombre_ct, m.nombre_mesa, pc.orden_prioridad ASC, pc.id_componente
    `
    
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching components:', error)
    return c.json({ error: 'Failed to fetch components' }, 500)
  }
})

// Get latest test results for components
app.get('/api/components/test-results/latest', authMiddleware, async (c) => {
  try {
    // CORRECTED: Partition by mesa + component + test type to get results per specific component in specific mesa
    const query = `
      WITH latest_results AS (
        SELECT 
          re.*,
          ROW_NUMBER() OVER (
            PARTITION BY re.id_mesa, re.id_componente_plantilla_1, re.id_tipo_ensayo 
            ORDER BY re.fecha_medicion DESC, re.id_resultado DESC
          ) as rn
        FROM resultados_ensayos re
        INNER JOIN mesas m ON m.id_mesa = re.id_mesa
        INNER JOIN inspecciones i ON re.id_inspeccion = i.id_inspeccion
        WHERE re.id_componente_plantilla_1 IS NOT NULL
      )
      SELECT 
        -- Create a unique component identifier per mesa
        CONCAT(lr.id_mesa, '_', lr.id_componente_plantilla_1) as id_componente,
        lr.id_mesa,
        lr.id_componente_plantilla_1,
        lr.id_tipo_ensayo,
        lr.resultado_numerico,
        lr.resultado_booleano,
        lr.resultado_texto,
        lr.comentario,
        lr.fecha_medicion,
        te.nombre_ensayo,
        te.tipo_resultado,
        te.unidad_medida
      FROM latest_results lr
      INNER JOIN tipos_ensayo te ON lr.id_tipo_ensayo = te.id_tipo_ensayo
      WHERE lr.rn = 1
      ORDER BY lr.id_mesa, lr.id_componente_plantilla_1, te.orden_prioridad ASC, te.grupo_ensayo, te.nombre_ensayo
    `
    
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching component test results:', error)
    return c.json({ error: 'Failed to fetch component test results' }, 500)
  }
})

// Get latest test results for a specific mesa
app.get('/api/mesas/:id/test-results/latest', authMiddleware, async (c) => {
  const mesaId = c.req.param('id')
  try {
    // Optimized query - only get results for the specific mesa
    const query = `
      WITH latest_results AS (
        SELECT 
          re.*,
          ROW_NUMBER() OVER (
            PARTITION BY re.id_componente_plantilla_1, re.id_tipo_ensayo 
            ORDER BY re.fecha_medicion DESC, re.id_resultado DESC
          ) as rn
        FROM resultados_ensayos re
        INNER JOIN inspecciones i ON re.id_inspeccion = i.id_inspeccion
        WHERE re.id_mesa = $1 AND re.id_componente_plantilla_1 IS NOT NULL
      )
      SELECT 
        -- Create a unique component identifier per mesa
        CONCAT(lr.id_mesa, '_', lr.id_componente_plantilla_1) as id_componente,
        lr.id_mesa,
        lr.id_componente_plantilla_1,
        lr.id_tipo_ensayo,
        lr.resultado_numerico,
        lr.resultado_booleano,
        lr.resultado_texto,
        lr.comentario,
        lr.fecha_medicion,
        te.nombre_ensayo,
        te.tipo_resultado,
        te.unidad_medida
      FROM latest_results lr
      INNER JOIN tipos_ensayo te ON lr.id_tipo_ensayo = te.id_tipo_ensayo
      WHERE lr.rn = 1
      ORDER BY lr.id_componente_plantilla_1, te.orden_prioridad ASC, te.grupo_ensayo, te.nombre_ensayo
    `
    
    const result = await pool.query(query, [mesaId])
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching mesa test results:', error)
    return c.json({ error: 'Failed to fetch mesa test results' }, 500)
  }
})

// Get latest test results for all mesas and test types
// Debug endpoint to check resultados_ensayos raw data
app.get('/api/resultados-ensayos/debug', authMiddleware, async (c) => {
  try {
    const query = `
      SELECT 
        re.id_resultado,
        re.id_mesa,
        re.id_tipo_ensayo,
        re.resultado_numerico,
        re.resultado_booleano,
        re.resultado_texto,
        re.fecha_medicion,
        te.nombre_ensayo,
        m.nombre_mesa
      FROM resultados_ensayos re
      JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      LEFT JOIN mesas m ON re.id_mesa = m.id_mesa
      ORDER BY re.id_mesa, te.nombre_ensayo, re.fecha_medicion DESC
    `
    
    const result = await pool.query(query)
    console.log('📊 Debug resultados_ensayos:')
    console.log('Total rows:', result.rows.length)
    
    // Group by tipo_ensayo to see distribution
    const byTipoEnsayo = result.rows.reduce((acc, row) => {
      const tipo = row.nombre_ensayo
      if (!acc[tipo]) acc[tipo] = []
      acc[tipo].push({
        id_mesa: row.id_mesa,
        nombre_mesa: row.nombre_mesa,
        fecha_medicion: row.fecha_medicion
      })
      return acc
    }, {})
    
    console.log('Distribution by tipo_ensayo:')
    Object.entries(byTipoEnsayo).forEach(([tipo, registros]) => {
      console.log(`  ${tipo}: ${registros.length} registros`)
      registros.slice(0, 3).forEach(r => {
        console.log(`    - Mesa ${r.id_mesa} (${r.nombre_mesa}) - ${r.fecha_medicion}`)
      })
    })
    
    return c.json({
      total_rows: result.rows.length,
      distribution: Object.fromEntries(
        Object.entries(byTipoEnsayo).map(([tipo, registros]) => [tipo, registros.length])
      ),
      sample_data: result.rows.slice(0, 10)
    })
  } catch (error) {
    console.error('Error in debug endpoint:', error)
    return c.json({ error: 'Debug query failed' }, 500)
  }
})

app.get('/api/resultados-ensayos/latest', authMiddleware, async (c) => {
  try {
    // Clean, simple query - only return results for the exact mesa they belong to
    const query = `
      WITH latest_results AS (
        SELECT 
          re.id_mesa,
          re.id_tipo_ensayo,
          re.resultado_numerico,
          re.resultado_booleano,
          re.resultado_texto,
          re.fecha_medicion,
          ROW_NUMBER() OVER (
            PARTITION BY re.id_mesa, re.id_tipo_ensayo 
            ORDER BY re.fecha_medicion DESC, re.id_resultado DESC
          ) as rn
        FROM resultados_ensayos re
        INNER JOIN mesas m ON m.id_mesa = re.id_mesa
        INNER JOIN inspecciones i ON re.id_inspeccion = i.id_inspeccion
      )
      SELECT 
        lr.id_mesa,
        lr.id_tipo_ensayo,
        lr.resultado_numerico,
        lr.resultado_booleano,
        lr.resultado_texto,
        lr.fecha_medicion,
        te.nombre_ensayo,
        te.tipo_resultado,
        te.unidad_medida
      FROM latest_results lr
      INNER JOIN tipos_ensayo te ON lr.id_tipo_ensayo = te.id_tipo_ensayo
      WHERE lr.rn = 1
      ORDER BY lr.id_mesa, te.orden_prioridad ASC, te.grupo_ensayo, te.nombre_ensayo
    `
    
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching latest test results:', error)
    return c.json({ error: 'Failed to fetch latest test results' }, 500)
  }
})

// Get resultados for an inspection
app.get('/api/inspecciones/:id/resultados', authMiddleware, async (c) => {
  const id_inspeccion = c.req.param('id')
  try {
    const query = `
      SELECT 
        re.*,
        te.nombre_ensayo,
        te.descripcion as ensayo_descripcion,
        te.tipo_resultado,
        te.unidad_medida,
        te.grupo_ensayo,
        m.nombre_mesa,
        pc1.tipo_elemento as componente1_tipo,
        pc1.descripcion_punto_montaje as componente1_descripcion,
        pc1.coord_x as componente1_x,
        pc1.coord_y as componente1_y,
        pc2.tipo_elemento as componente2_tipo,
        pc2.descripcion_punto_montaje as componente2_descripcion,
        pc2.coord_x as componente2_x,
        pc2.coord_y as componente2_y
      FROM resultados_ensayos re
      JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      JOIN mesas m ON re.id_mesa = m.id_mesa
      JOIN plantilla_componentes pc1 ON re.id_componente_plantilla_1 = pc1.id_componente
      LEFT JOIN plantilla_componentes pc2 ON re.id_componente_plantilla_2 = pc2.id_componente
      WHERE re.id_inspeccion = $1
      ORDER BY re.fecha_medicion DESC
    `
    const result = await pool.query(query, [id_inspeccion])
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching inspection results:', error)
    return c.json({ error: 'Failed to fetch inspection results' }, 500)
  }
})

// Dashboard statistics endpoint
app.get('/api/dashboard/estadisticas', authMiddleware, async (c) => {
  try {
    console.log('📊 Fetching real dashboard statistics...')
    
    // Get total number of tests
    const totalEnsayosQuery = 'SELECT COUNT(*) as total FROM resultados_ensayos'
    const totalEnsayosResult = await pool.query(totalEnsayosQuery)
    const totalEnsayos = parseInt(totalEnsayosResult.rows[0].total)
    
    // Get failed tests using comentario field (OK = correcto, NOK = fallido)
    const ensayosFallidosQuery = `
      SELECT 
        COUNT(CASE WHEN te.tipo_resultado = 'BOOLEANO' THEN 1 END) as total_booleanos,
        COUNT(CASE WHEN te.tipo_resultado = 'NUMERICO' THEN 1 END) as total_numericos,
        COUNT(CASE WHEN te.tipo_resultado = 'TEXTO' THEN 1 END) as total_texto,
        COUNT(CASE WHEN r.comentario = 'NOK' AND te.tipo_resultado = 'BOOLEANO' THEN 1 END) as fallidos_booleanos,
        COUNT(CASE WHEN r.comentario = 'NOK' AND te.tipo_resultado = 'NUMERICO' THEN 1 END) as fallidos_numericos,
        COUNT(CASE WHEN r.comentario = 'NOK' AND te.tipo_resultado = 'TEXTO' THEN 1 END) as fallidos_texto,
        COUNT(CASE WHEN r.comentario = 'NOK' THEN 1 END) as total_fallidos
      FROM resultados_ensayos re
      JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      LEFT JOIN reglas_resultados_ensayos r ON re.id_tipo_ensayo = r.id_tipo_ensayo
      WHERE (
        (te.tipo_resultado = 'BOOLEANO' AND (
          (r.valor_booleano IS NOT NULL AND re.resultado_booleano = r.valor_booleano) OR
          (r.valor_booleano IS NULL AND re.resultado_booleano = false)
        )) OR
        (te.tipo_resultado = 'NUMERICO' AND re.resultado_numerico IS NOT NULL AND (
          (r.tipo_condicion = '=' AND re.resultado_numerico = r.valor_numerico_1) OR
          (r.tipo_condicion = '<>' AND re.resultado_numerico != r.valor_numerico_1) OR
          (r.tipo_condicion = '>' AND re.resultado_numerico > r.valor_numerico_1) OR
          (r.tipo_condicion = '<' AND re.resultado_numerico < r.valor_numerico_1) OR
          (r.tipo_condicion = '>=' AND re.resultado_numerico >= r.valor_numerico_1) OR
          (r.tipo_condicion = '<=' AND re.resultado_numerico <= r.valor_numerico_1) OR
          (r.tipo_condicion = 'ENTRE' AND re.resultado_numerico >= r.valor_numerico_1 AND re.resultado_numerico <= r.valor_numerico_2) OR
          (r.tipo_condicion = 'FUERA_DE' AND (re.resultado_numerico < r.valor_numerico_1 OR re.resultado_numerico > r.valor_numerico_2))
        )) OR
        (te.tipo_resultado = 'TEXTO' AND re.resultado_texto IS NOT NULL AND (
          (r.tipo_condicion = '=' AND re.resultado_texto = r.valor_texto) OR
          (r.tipo_condicion = '<>' AND re.resultado_texto != r.valor_texto)
        ))
      )
    `
    
    const ensayosFallidosResult = await pool.query(ensayosFallidosQuery)
    const fallosData = ensayosFallidosResult.rows[0]
    
    const totalEnsayosBooleanos = parseInt(fallosData.total_booleanos || 0)
    const ensayosFallidosBooleanos = parseInt(fallosData.fallidos_booleanos || 0)
    const ensayosFallidosNumericos = parseInt(fallosData.fallidos_numericos || 0)
    const ensayosFallidosTexto = parseInt(fallosData.fallidos_texto || 0)
    const ensayosFallidos = parseInt(fallosData.total_fallidos || 0)
    
    // Calculate success rate
    const tasaExito = totalEnsayos > 0 ? Math.round(((totalEnsayos - ensayosFallidos) / totalEnsayos) * 100 * 10) / 10 : 100
    
    // Get number of inspected tables
    const mesasInspeccionadasQuery = 'SELECT COUNT(DISTINCT id_mesa) as total FROM resultados_ensayos'
    const mesasInspeccionadasResult = await pool.query(mesasInspeccionadasQuery)
    const mesasInspeccionadas = parseInt(mesasInspeccionadasResult.rows[0].total)
    
    // Get active inspections
    const inspeccionesActivasQuery = "SELECT COUNT(*) as total FROM inspecciones WHERE estado = 'EN_PROCESO'"
    const inspeccionesActivasResult = await pool.query(inspeccionesActivasQuery)
    const inspeccionesActivas = parseInt(inspeccionesActivasResult.rows[0].total)
    
    // Get tests by type (HINCAS vs POT)
    const ensayosPorTipoQuery = `
      SELECT 
        COALESCE(te.grupo_ensayo, 'SIN_GRUPO') as tipo, 
        COUNT(re.id_resultado) as cantidad
      FROM resultados_ensayos re
      JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      GROUP BY te.grupo_ensayo
      ORDER BY cantidad DESC
    `
    const ensayosPorTipoResult = await pool.query(ensayosPorTipoQuery)
    const ensayosPorTipo = ensayosPorTipoResult.rows
    
    // Get results by test result type using NOK comentario
    const ensayosPorTipoResultadoQuery = `
      SELECT 
        te.tipo_resultado as tipo,
        COUNT(re.id_resultado) as cantidad,
        COUNT(CASE WHEN r.comentario = 'NOK' THEN 1 END) as fallidos_booleanos
      FROM resultados_ensayos re
      JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      LEFT JOIN reglas_resultados_ensayos r ON re.id_tipo_ensayo = r.id_tipo_ensayo
      GROUP BY te.tipo_resultado
      ORDER BY cantidad DESC
    `
    const ensayosPorTipoResultadoResult = await pool.query(ensayosPorTipoResultadoQuery)
    const ensayosPorTipoResultado = ensayosPorTipoResultadoResult.rows
    
    // Get temporal evolution (last 12 months) using NOK comentario
    const evolucionTemporalQuery = `
      SELECT 
        TO_CHAR(re.fecha_medicion, 'YYYY-MM') as fecha,
        COUNT(re.id_resultado) as cantidad,
        COUNT(CASE WHEN r.comentario = 'NOK' THEN 1 END) as fallidos
      FROM resultados_ensayos re
      LEFT JOIN reglas_resultados_ensayos r ON re.id_tipo_ensayo = r.id_tipo_ensayo
      WHERE re.fecha_medicion >= CURRENT_DATE - INTERVAL '12 months'
      GROUP BY TO_CHAR(re.fecha_medicion, 'YYYY-MM')
      ORDER BY fecha
    `
    const evolucionTemporalResult = await pool.query(evolucionTemporalQuery)
    const evolucionTemporal = evolucionTemporalResult.rows
    
    // Get categories showing OK vs NOK results
    const resultadosPorCategoriaQuery = `
      SELECT 
        CASE 
          WHEN r.comentario = 'OK' THEN 'Resultados Correctos'
          WHEN r.comentario = 'NOK' THEN 'Resultados Fallidos'
          ELSE COALESCE(r.comentario, 'Sin categoría')
        END as categoria,
        te.tipo_resultado,
        COUNT(re.id_resultado) as total_ensayos,
        COUNT(CASE WHEN r.comentario = 'NOK' THEN 1 END) as fallidos,
        CASE WHEN r.comentario = 'NOK' THEN '#F54927' ELSE '#10b981' END as resaltado
      FROM reglas_resultados_ensayos r
      LEFT JOIN resultados_ensayos re ON r.id_tipo_ensayo = re.id_tipo_ensayo
      LEFT JOIN tipos_ensayo te ON r.id_tipo_ensayo = te.id_tipo_ensayo
      WHERE r.comentario IN ('OK', 'NOK')
      GROUP BY r.comentario, te.tipo_resultado
      HAVING COUNT(re.id_resultado) > 0
      ORDER BY 
        CASE WHEN r.comentario = 'NOK' THEN 0 ELSE 1 END,
        fallidos DESC
      LIMIT 8
    `
    const resultadosPorCategoriaResult = await pool.query(resultadosPorCategoriaQuery)
    const resultadosPorCategoria = resultadosPorCategoriaResult.rows

    // Get most failed test types using NOK comentario
    const tiposEnsayoMasFallidosQuery = `
      SELECT 
        te.nombre_ensayo,
        te.tipo_resultado,
        CASE 
          WHEN r.comentario = 'NOK' THEN 'Fallidos'
          WHEN r.comentario = 'OK' THEN 'Correctos'
          ELSE 'General'
        END as categoria,
        COUNT(re.id_resultado) as total_ensayos,
        COUNT(CASE WHEN r.comentario = 'NOK' THEN 1 END) as fallidos,
        CASE 
          WHEN COUNT(re.id_resultado) > 0 THEN 
            ROUND((COUNT(CASE WHEN r.comentario = 'NOK' THEN 1 END)::numeric / COUNT(re.id_resultado)) * 100, 1)
          ELSE 0
        END as porcentaje_fallos
      FROM tipos_ensayo te
      LEFT JOIN resultados_ensayos re ON te.id_tipo_ensayo = re.id_tipo_ensayo
      LEFT JOIN reglas_resultados_ensayos r ON te.id_tipo_ensayo = r.id_tipo_ensayo
      WHERE r.comentario = 'NOK'
      GROUP BY te.id_tipo_ensayo, te.nombre_ensayo, te.tipo_resultado, r.comentario
      HAVING COUNT(re.id_resultado) > 0
      ORDER BY fallidos DESC, porcentaje_fallos DESC
      LIMIT 8
    `
    const tiposEnsayoMasFallidosResult = await pool.query(tiposEnsayoMasFallidosQuery)
    const tiposEnsayoMasFallidos = tiposEnsayoMasFallidosResult.rows
    
    const estadisticas = {
      totalEnsayos,
      ensayosFallidos,
      ensayosFallidosBooleanos,
      ensayosFallidosNumericos,
      ensayosFallidosTexto,
      totalEnsayosBooleanos,
      tasaExito,
      mesasInspeccionadas,
      inspeccionesActivas,
      ensayosPorTipo,
      ensayosPorTipoResultado,
      evolucionTemporal,
      tiposEnsayoMasFallidos,
      resultadosPorCategoria
    }
    
    console.log('📈 Real dashboard statistics generated:', {
      ...estadisticas,
      tiposEnsayoMasFallidos: estadisticas.tiposEnsayoMasFallidos.length
    })
    return c.json(estadisticas)
    
  } catch (error) {
    console.error('Error fetching dashboard statistics:', error)
    return c.json({ error: 'Failed to fetch dashboard statistics' }, 500)
  }
})

// Report generation endpoints
app.get('/api/inspecciones', authMiddleware, async (c) => {
  try {
    console.log('📋 Fetching all inspections...')
    
    const query = `
      SELECT 
        id_inspeccion,
        id_usuario,
        fecha_inicio,
        fecha_fin,
        descripcion,
        estado
      FROM inspecciones
      ORDER BY fecha_inicio DESC
      LIMIT 50
    `
    
    const result = await pool.query(query)
    console.log(`📋 Found ${result.rows.length} inspections`)
    return c.json(result.rows)
    
  } catch (error) {
    console.error('Error fetching inspections:', error)
    return c.json({ error: 'Failed to fetch inspections' }, 500)
  }
})

app.get('/api/inspecciones/:id/mesas', authMiddleware, async (c) => {
  try {
    const id_inspeccion = c.req.param('id')
    console.log(`📋 Fetching mesas for inspection ${id_inspeccion}...`)
    
    const query = `
      SELECT DISTINCT 
        m.id_mesa,
        m.id_ct,
        m.nombre_mesa,
        m.coord_x,
        m.coord_y,
        ct.nombre_ct
      FROM mesas m
      JOIN resultados_ensayos re ON m.id_mesa = re.id_mesa
      LEFT JOIN cts ct ON m.id_ct = ct.id_ct
      WHERE re.id_inspeccion = $1
      ORDER BY m.id_mesa
    `
    
    const result = await pool.query(query, [id_inspeccion])
    console.log(`📋 Found ${result.rows.length} mesas for inspection ${id_inspeccion}`)
    return c.json(result.rows)
    
  } catch (error) {
    console.error('Error fetching inspection mesas:', error)
    return c.json({ error: 'Failed to fetch inspection mesas' }, 500)
  }
})

app.get('/api/inspecciones/:id/report-data', authMiddleware, async (c) => {
  try {
    const id_inspeccion = c.req.param('id')
    console.log(`📋 Generating report data for inspection ${id_inspeccion}...`)
    
    // Get inspection details
    const inspectionQuery = `
      SELECT 
        id_inspeccion,
        id_usuario,
        fecha_inicio,
        fecha_fin,
        descripcion,
        estado
      FROM inspecciones
      WHERE id_inspeccion = $1
    `
    const inspectionResult = await pool.query(inspectionQuery, [id_inspeccion])
    const inspection = inspectionResult.rows[0]
    
    if (!inspection) {
      return c.json({ error: 'Inspection not found' }, 404)
    }
    
    // Get mesas with their test results
    const mesasQuery = `
      SELECT DISTINCT 
        m.id_mesa,
        m.id_ct,
        m.nombre_mesa,
        m.coord_x,
        m.coord_y,
        ct.nombre_ct
      FROM mesas m
      JOIN resultados_ensayos re ON m.id_mesa = re.id_mesa
      LEFT JOIN cts ct ON m.id_ct = ct.id_ct
      WHERE re.id_inspeccion = $1
      ORDER BY m.id_mesa
    `
    const mesasResult = await pool.query(mesasQuery, [id_inspeccion])
    const mesas = mesasResult.rows
    
    // Get test results for each mesa
    const mesasWithResults = []
    for (const mesa of mesas) {
      const resultsQuery = `
        SELECT 
          re.id_resultado,
          re.resultado_numerico,
          re.resultado_booleano,
          re.resultado_texto,
          re.fecha_medicion,
          re.comentario,
          te.nombre_ensayo,
          te.tipo_resultado,
          te.unidad_medida,
          pc.descripcion_punto_montaje,
          pc.coord_x as componente_x,
          pc.coord_y as componente_y
        FROM resultados_ensayos re
        JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
        LEFT JOIN plantilla_componentes pc ON re.id_componente_plantilla_1 = pc.id_componente
        WHERE re.id_inspeccion = $1 AND re.id_mesa = $2
        ORDER BY pc.orden_prioridad ASC, te.orden_prioridad ASC
      `
      const resultsResult = await pool.query(resultsQuery, [id_inspeccion, mesa.id_mesa])
      
      mesasWithResults.push({
        ...mesa,
        resultados: resultsResult.rows
      })
    }
    
    const reportData = {
      inspection,
      mesas: mesasWithResults,
      generated_at: new Date().toISOString()
    }
    
    console.log(`📋 Generated report data for ${mesas.length} mesas`)
    return c.json(reportData)
    
  } catch (error) {
    console.error('Error generating report data:', error)
    return c.json({ error: 'Failed to generate report data' }, 500)
  }
})

// ================================
// EXPORT ENDPOINTS FOR POWER QUERY
// ================================

// Export inspecciones table
app.get('/api/export/inspecciones', exportAuthMiddleware, async (c) => {
  try {
    const result = await pool.query(`
      SELECT 
        i.*,
        u.username as usuario_nombre
      FROM inspecciones i
      LEFT JOIN usuarios u ON i.id_usuario = u.id
      ORDER BY i.fecha_inicio DESC
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting inspecciones:', error)
    return c.json({ error: 'Failed to export inspecciones' }, 500)
  }
})

// Export mesas table
app.get('/api/export/mesas', exportAuthMiddleware, async (c) => {
  try {
    const result = await pool.query(`
      SELECT 
        m.*,
        c.nombre_ct,
        p.nombre_plantilla,
        p.dimension_x,
        p.dimension_y
      FROM mesas m
      LEFT JOIN cts c ON m.id_ct = c.id_ct
      LEFT JOIN mesa_plantillas p ON m.id_plantilla = p.id_plantilla
      ORDER BY m.id_mesa
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting mesas:', error)
    return c.json({ error: 'Failed to export mesas' }, 500)
  }
})

// Export resultados_ensayos table
app.get('/api/export/resultados-ensayos', exportAuthMiddleware, async (c) => {
  try {
    const result = await pool.query(`
      SELECT 
        re.*,
        te.nombre_ensayo,
        te.descripcion as ensayo_descripcion,
        te.unidad_medida,
        te.grupo_ensayo,
        te.tipo_resultado,
        m.nombre_mesa,
        m.id_ct,
        c.nombre_ct,
        pc1.descripcion_punto_montaje as componente_1_descripcion,
        pc1.tipo_elemento as componente_1_tipo,
        pc1.coord_x as componente_1_coord_x,
        pc1.coord_y as componente_1_coord_y,
        pc2.descripcion_punto_montaje as componente_2_descripcion,
        pc2.tipo_elemento as componente_2_tipo,
        pc2.coord_x as componente_2_coord_x,
        pc2.coord_y as componente_2_coord_y
      FROM resultados_ensayos re
      LEFT JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      LEFT JOIN mesas m ON re.id_mesa = m.id_mesa
      LEFT JOIN cts c ON m.id_ct = c.id_ct
      LEFT JOIN plantilla_componentes pc1 ON re.id_componente_plantilla_1 = pc1.id_componente
      LEFT JOIN plantilla_componentes pc2 ON re.id_componente_plantilla_2 = pc2.id_componente
      ORDER BY re.id_mesa, te.nombre_ensayo, re.fecha_medicion DESC
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting resultados_ensayos:', error)
    return c.json({ error: 'Failed to export resultados_ensayos' }, 500)
  }
})

// Export tipos_ensayo table
app.get('/api/export/tipos-ensayo', exportAuthMiddleware, async (c) => {
  try {
    const result = await pool.query(`
      SELECT * FROM tipos_ensayo ORDER BY grupo_ensayo, orden_prioridad, nombre_ensayo
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting tipos_ensayo:', error)
    return c.json({ error: 'Failed to export tipos_ensayo' }, 500)
  }
})

// Export reglas_resultados_ensayos table  
app.get('/api/export/reglas-resultados-ensayos', exportAuthMiddleware, async (c) => {
  try {
    const result = await pool.query(`
      SELECT 
        r.*,
        te.nombre_ensayo,
        te.tipo_resultado
      FROM reglas_resultados_ensayos r
      LEFT JOIN tipos_ensayo te ON r.id_tipo_ensayo = te.id_tipo_ensayo
      ORDER BY r.id_tipo_ensayo, r.prioridad
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting reglas_resultados_ensayos:', error)
    return c.json({ error: 'Failed to export reglas_resultados_ensayos' }, 500)
  }
})

// Export plantilla_componentes table
app.get('/api/export/plantilla-componentes', exportAuthMiddleware, async (c) => {
  try {
    const result = await pool.query(`
      SELECT 
        pc.*,
        p.nombre_plantilla
      FROM plantilla_componentes pc
      LEFT JOIN mesa_plantillas p ON pc.id_plantilla = p.id_plantilla
      ORDER BY pc.id_plantilla, pc.orden_prioridad, pc.id_componente
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting plantilla_componentes:', error)
    return c.json({ error: 'Failed to export plantilla_componentes' }, 500)
  }
})

// Export specific inspection data (JSON format)
app.get('/api/export/inspecciones/:id/resultados', exportAuthMiddleware, async (c) => {
  try {
    const inspectionId = c.req.param('id')
    const result = await pool.query(`
      SELECT 
        re.*,
        te.nombre_ensayo,
        te.descripcion as ensayo_descripcion,
        te.unidad_medida,
        te.grupo_ensayo,
        te.tipo_resultado,
        m.nombre_mesa,
        m.id_ct,
        c.nombre_ct,
        pc1.descripcion_punto_montaje as componente_1_descripcion,
        pc1.tipo_elemento as componente_1_tipo,
        pc1.coord_x as componente_1_coord_x,
        pc1.coord_y as componente_1_coord_y
      FROM resultados_ensayos re
      LEFT JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      LEFT JOIN mesas m ON re.id_mesa = m.id_mesa
      LEFT JOIN cts c ON m.id_ct = c.id_ct
      LEFT JOIN plantilla_componentes pc1 ON re.id_componente_plantilla_1 = pc1.id_componente
      WHERE re.id_inspeccion = $1
      ORDER BY re.id_mesa, te.nombre_ensayo, re.fecha_medicion DESC
    `, [inspectionId])
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting inspection results:', error)
    return c.json({ error: 'Failed to export inspection results' }, 500)
  }
})

// Start the server
const port = process.env.PORT ? parseInt(process.env.PORT) : 8787

serve({
  fetch: app.fetch,
  port,
})

console.log(`🚀 Server running on http://localhost:${port}`)
