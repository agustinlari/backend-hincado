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
  
  const logoutUrl = `${keycloakUrl}/realms/${realm}/protocol/openid-connect/logout`
  
  return c.json({ logoutUrl })
})

// Middleware for protected routes
const authMiddleware = async (c: any, next: any) => {
  // Skip auth in development mode if enabled
  if (process.env.ENABLE_DEV_AUTH === 'true') {
    c.set('user', { sub: '1', email: 'dev@example.com', name: 'Dev User' })
    return next()
  }
  
  const authHeader = c.req.header('Authorization')
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
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
    return next()
  } catch (error: any) {
    console.error('Auth middleware failed:', error.message);
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
  try {
    const query = `
      SELECT 
        pc.id_componente,
        pc.tipo_elemento,
        pc.coord_x,
        pc.coord_y,
        pc.descripcion_punto_montaje
      FROM mesas m
      JOIN plantilla_componentes pc ON m.id_plantilla = pc.id_plantilla
      WHERE m.id_mesa = $1
      ORDER BY pc.tipo_elemento, pc.coord_x, pc.coord_y
    `
    const result = await pool.query(query, [id])
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
        maximo_admisible
      FROM tipos_ensayo
      ORDER BY grupo_ensayo, nombre_ensayo
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

// ==================== INSPECCIONES ====================

// Create a new inspection session
app.post('/api/inspecciones', authMiddleware, async (c) => {
  try {
    const body = await c.req.json()
    const { descripcion } = body
    
    // Get user ID from auth token
    const user = c.get('user')
    const id_usuario = 1 // Por ahora usamos un ID fijo, después podríamos extraerlo del token
    
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

// Get all inspections (simplified for now - later filter by mesa through resultados_ensayos)
app.get('/api/mesas/:id/inspecciones', authMiddleware, async (c) => {
  try {
    const query = `
      SELECT 
        id_inspeccion,
        fecha_inicio,
        fecha_fin,
        descripcion,
        estado,
        id_usuario
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
      resultado_texto
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
        resultado_numerico, resultado_booleano, resultado_texto
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `
    
    const result = await pool.query(query, [
      id_inspeccion, id_tipo_ensayo, id_mesa,
      id_componente_plantilla_1, id_componente_plantilla_2,
      resultado_numerico, resultado_booleano, resultado_texto
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

// Start the server
const port = process.env.PORT ? parseInt(process.env.PORT) : 8787

serve({
  fetch: app.fetch,
  port,
})

console.log(`🚀 Server running on http://localhost:${port}`)
