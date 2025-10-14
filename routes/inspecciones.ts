import { Hono } from 'hono'
import { Pool } from 'pg'

// User cache to store user information
// Maps both UUID (from JWT) and integer ID (from DB) to user info
const userCache = new Map<string, { name?: string, preferred_username?: string, userId?: number, uuid?: string }>()
const idToUuidCache = new Map<number, string>() // Maps integer ID back to UUID

// Function to get or fetch user info by integer ID
async function getUserInfo(userId: string): Promise<{ name?: string, preferred_username?: string }> {
  const numericUserId = parseInt(userId)

  // First check if we have UUID mapping for this numeric ID
  const uuid = idToUuidCache.get(numericUserId)
  if (uuid && userCache.has(uuid)) {
    return userCache.get(uuid)!
  }

  // Check cache by string ID directly
  if (userCache.has(userId)) {
    return userCache.get(userId)!
  }

  // For now, return a placeholder. In a real implementation, you would:
  // 1. Query a local users table, or
  // 2. Make a call to Keycloak Admin API to get user info, or
  // 3. Store user info when they first authenticate
  const userInfo = { name: `Usuario ${userId}`, preferred_username: `user${userId}` }
  userCache.set(userId, userInfo)
  return userInfo
}

// Function to store user info and create mappings
function storeUserInfo(uuid: string, userId: number, userInfo: { name?: string, preferred_username?: string }) {
  // Store in cache with UUID as key
  userCache.set(uuid, { ...userInfo, userId, uuid })
  // Create reverse mapping from integer ID to UUID
  idToUuidCache.set(userId, uuid)
}

export function createInspeccionesRouter(pool: Pool, authMiddleware: any) {
  const router = new Hono()

  // Create a new inspection session
  router.post('/api/inspecciones', authMiddleware, async (c) => {
    try {
      const body = await c.req.json()
      const { descripcion } = body

      // Get user ID from auth token
      const user = c.get('user')

      // Extract user ID from the JWT token (sub field contains the user ID)
      // For now, we'll use a hash of the sub to create a consistent integer ID
      const id_usuario = user?.sub ? Math.abs(user.sub.split('').reduce((hash, char) => {
        return ((hash << 5) - hash + char.charCodeAt(0)) & 0xffffffff
      }, 0)) : 1

      console.log('👤 Creando inspección para usuario:', { id_usuario, userSub: user?.sub, username: user?.preferred_username })

      // Store user info in cache for future lookups
      if (user?.sub) {
        storeUserInfo(user.sub, id_usuario, {
          name: user.name,
          preferred_username: user.preferred_username
        })
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
  router.patch('/api/inspecciones/:id', authMiddleware, async (c) => {
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
  router.get('/api/inspecciones', authMiddleware, async (c) => {
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

  // Delete inspection
  router.delete('/api/inspecciones/:id', authMiddleware, async (c) => {
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
  router.get('/api/mesas/:id/inspecciones', authMiddleware, async (c) => {
    try {
      const user = c.get('user')

      // Get query parameters for filtering
      const showAll = c.req.query('showAll') === 'true'
      const filterByUser = c.req.query('filterByUser') !== 'false' // Default to true
      const filterByStatus = c.req.query('filterByStatus') !== 'false' // Default to true

      // Store current user info in cache if available
      let currentUserId = 1
      if (user?.sub) {
        currentUserId = Math.abs(user.sub.split('').reduce((hash, char) => {
          return ((hash << 5) - hash + char.charCodeAt(0)) & 0xffffffff
        }, 0))

        storeUserInfo(user.sub, currentUserId, {
          name: user.name,
          preferred_username: user.preferred_username
        })
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
      `

      const conditions = []
      const params = []
      let paramIndex = 1

      // Apply filters if not showing all
      if (!showAll) {
        if (filterByUser) {
          conditions.push(`id_usuario = $${paramIndex}`)
          params.push(currentUserId)
          paramIndex++
        }

        if (filterByStatus) {
          conditions.push(`estado = $${paramIndex}`)
          params.push('EN_PROCESO')
          paramIndex++
        }
      }

      if (conditions.length > 0) {
        query += ` WHERE ${conditions.join(' AND ')}`
      }

      query += ` ORDER BY fecha_inicio DESC`

      console.log('🔍 Query inspecciones:', { query, params, showAll, currentUserId, userSub: user?.sub })

      const result = await pool.query(query, params)

      // Enrich inspections with user information
      const enrichedInspections = await Promise.all(result.rows.map(async (inspection) => {
        const userInfo = await getUserInfo(inspection.id_usuario.toString())
        return {
          ...inspection,
          usuario_nombre: userInfo.name,
          usuario_username: userInfo.preferred_username
        }
      }))

      return c.json(enrichedInspections)
    } catch (error) {
      console.error('Error fetching inspections:', error)
      return c.json({ error: 'Failed to fetch inspections' }, 500)
    }
  })

  // Get resultados for an inspection
  router.get('/api/inspecciones/:id/resultados', authMiddleware, async (c) => {
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

  return router
}
