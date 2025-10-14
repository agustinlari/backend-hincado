import { Hono } from 'hono'
import { Pool } from 'pg'

export function createEnsayosRouter(pool: Pool, authMiddleware: any) {
  const router = new Hono()

  // ==================== TIPOS DE ENSAYO ====================

  // Get all tipos de ensayo
  router.get('/api/tipos-ensayo', authMiddleware, async (c) => {
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
  router.post('/api/tipos-ensayo', authMiddleware, async (c) => {
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
  router.get('/api/reglas-resultados-ensayos', authMiddleware, async (c) => {
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
  router.post('/api/reglas-resultados-ensayos', authMiddleware, async (c) => {
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
  router.put('/api/reglas-resultados-ensayos/:id', authMiddleware, async (c) => {
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
  router.delete('/api/reglas-resultados-ensayos/:id', authMiddleware, async (c) => {
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

  // ==================== RESULTADOS DE ENSAYOS ====================

  // Create resultado de ensayo
  router.post('/api/resultados-ensayos', authMiddleware, async (c) => {
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

      // All ensayos use the same logic now
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
  router.get('/api/components', authMiddleware, async (c) => {
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
  router.get('/api/components/test-results/latest', authMiddleware, async (c) => {
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
  router.get('/api/mesas/:id/test-results/latest', authMiddleware, async (c) => {
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
  router.get('/api/resultados-ensayos/debug', authMiddleware, async (c) => {
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

  router.get('/api/resultados-ensayos/latest', authMiddleware, async (c) => {
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

  // Delete the latest resultado for a specific mesa and tipo_ensayo
  router.delete('/api/resultados-ensayos', authMiddleware, async (c) => {
    try {
      const body = await c.req.json()
      const { id_mesa, id_componente, id_tipo_ensayo } = body

      if (!id_mesa || !id_componente || !id_tipo_ensayo) {
        return c.json({ error: 'Missing required parameters: id_mesa, id_componente, id_tipo_ensayo' }, 400)
      }

      const client = await pool.connect()

      try {
        await client.query('BEGIN')

        // Find the latest resultado for this mesa/componente/tipo_ensayo combination
        const latestQuery = `
          SELECT id_resultado, resultado_numerico
          FROM resultados_ensayos
          WHERE id_mesa = $1 AND id_componente_plantilla_1 = $2 AND id_tipo_ensayo = $3
          ORDER BY fecha_medicion DESC, id_resultado DESC
          LIMIT 1
        `
        const latestResult = await client.query(latestQuery, [id_mesa, id_componente, id_tipo_ensayo])

        if (latestResult.rows.length === 0) {
          await client.query('ROLLBACK')
          return c.json({ error: 'No resultado found to delete' }, 404)
        }

        const resultadoToDelete = latestResult.rows[0]

        // Delete the resultado
        const deleteQuery = `
          DELETE FROM resultados_ensayos
          WHERE id_resultado = $1
        `
        await client.query(deleteQuery, [resultadoToDelete.id_resultado])

        await client.query('COMMIT')
        return c.json({ success: true, message: 'Resultado deleted successfully' })

      } catch (error) {
        await client.query('ROLLBACK')
        throw error
      } finally {
        client.release()
      }

    } catch (error) {
      console.error('Error deleting resultado:', error)
      return c.json({ error: 'Failed to delete resultado' }, 500)
    }
  })

  return router
}
