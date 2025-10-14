import { Hono } from 'hono'
import { Pool } from 'pg'

// Router for data export endpoints (Power Query, Excel, etc.)
export function createExportsRouter(pool: Pool, exportAuthMiddleware: any) {
  const router = new Hono()

  // Export inspecciones table
  router.get('/api/export/inspecciones', exportAuthMiddleware, async (c) => {
    try {
      const result = await pool.query(`
        SELECT * FROM inspecciones
        ORDER BY fecha_inicio DESC
      `)
      return c.json(result.rows)
    } catch (error: any) {
      console.error('Error exporting inspecciones:', error)
      return c.json({
        error: 'Failed to export inspecciones',
        details: error.message
      }, 500)
    }
  })

  // Export inspecciones table (alternative endpoint to avoid route conflicts)
  router.get('/api/export/inspecciones-data', exportAuthMiddleware, async (c) => {
    try {
      const result = await pool.query(`
        SELECT * FROM inspecciones
        ORDER BY fecha_inicio DESC
      `)
      return c.json(result.rows)
    } catch (error: any) {
      console.error('Error exporting inspecciones data:', error)
      return c.json({
        error: 'Failed to export inspecciones data',
        details: error.message
      }, 500)
    }
  })

  // Export mesas table
  router.get('/api/export/mesas', exportAuthMiddleware, async (c) => {
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
  router.get('/api/export/resultados-ensayos', exportAuthMiddleware, async (c) => {
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
  router.get('/api/export/tipos-ensayo', exportAuthMiddleware, async (c) => {
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
  router.get('/api/export/reglas-resultados-ensayos', exportAuthMiddleware, async (c) => {
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
  router.get('/api/export/plantilla-componentes', exportAuthMiddleware, async (c) => {
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
  router.get('/api/export/inspecciones/:id/resultados', exportAuthMiddleware, async (c) => {
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

  return router
}
