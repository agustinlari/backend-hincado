import { Hono } from 'hono'
import { Pool } from 'pg'

export function createMesasRouter(pool: Pool, authMiddleware: any) {
  const router = new Hono()

  // Get all mesas with their CT and plantilla info
  router.get('/api/mesas', authMiddleware, async (c) => {
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
        ORDER BY m.id_mesa
      `
      const result = await pool.query(query)
      return c.json(result.rows)
    } catch (error) {
      console.error('Error fetching mesas:', error)
      return c.json({ error: 'Failed to fetch mesas' }, 500)
    }
  })

  // Get mesas with all tests OK (most recent tests have resaltado = 'E5FAE1')
  // AND all components have "Altura hinca" test (id_tipo_ensayo=2) with OK result
  // AND if POT tests (id_tipo_ensayo=33) exist, all must be OK (POT tests are optional)
  // IMPORTANT: This route must be BEFORE /api/mesas/:id to avoid conflict
  router.get('/api/mesas/ensayos-ok', authMiddleware, async (c) => {
    try {
      const query = `
        WITH latest_results AS (
          -- Get the most recent test result for each (mesa, component, test_type) combination
          SELECT
            re.*,
            ROW_NUMBER() OVER (
              PARTITION BY re.id_mesa, re.id_componente_plantilla_1, re.id_tipo_ensayo
              ORDER BY re.fecha_medicion DESC, re.id_resultado DESC
            ) as rn
          FROM resultados_ensayos re
          WHERE re.id_componente_plantilla_1 IS NOT NULL
        ),
        evaluated_results AS (
          -- Evaluate each result against its rules to get the resaltado color
          SELECT
            lr.id_mesa,
            lr.id_componente_plantilla_1,
            lr.id_tipo_ensayo,
            lr.resultado_numerico,
            lr.resultado_booleano,
            lr.resultado_texto,
            r.resaltado,
            r.prioridad
          FROM latest_results lr
          INNER JOIN reglas_resultados_ensayos r ON lr.id_tipo_ensayo = r.id_tipo_ensayo
          WHERE lr.rn = 1
            AND (
              -- Numeric conditions
              (lr.resultado_numerico IS NOT NULL AND r.valor_numerico_1 IS NOT NULL AND (
                (r.tipo_condicion = '=' AND lr.resultado_numerico = r.valor_numerico_1) OR
                (r.tipo_condicion = '<>' AND lr.resultado_numerico <> r.valor_numerico_1) OR
                (r.tipo_condicion = '>' AND lr.resultado_numerico > r.valor_numerico_1) OR
                (r.tipo_condicion = '<' AND lr.resultado_numerico < r.valor_numerico_1) OR
                (r.tipo_condicion = '>=' AND lr.resultado_numerico >= r.valor_numerico_1) OR
                (r.tipo_condicion = '<=' AND lr.resultado_numerico <= r.valor_numerico_1) OR
                (r.tipo_condicion = 'ENTRE' AND lr.resultado_numerico BETWEEN r.valor_numerico_1 AND r.valor_numerico_2) OR
                (r.tipo_condicion = 'FUERA_DE' AND lr.resultado_numerico NOT BETWEEN r.valor_numerico_1 AND r.valor_numerico_2)
              ))
              OR
              -- Boolean conditions
              (lr.resultado_booleano IS NOT NULL AND r.valor_booleano IS NOT NULL AND (
                (r.tipo_condicion = '=' AND lr.resultado_booleano = r.valor_booleano) OR
                (r.tipo_condicion = '<>' AND lr.resultado_booleano <> r.valor_booleano)
              ))
              OR
              -- Text conditions
              (lr.resultado_texto IS NOT NULL AND r.valor_texto IS NOT NULL AND (
                (r.tipo_condicion = '=' AND lr.resultado_texto = r.valor_texto) OR
                (r.tipo_condicion = '<>' AND lr.resultado_texto <> r.valor_texto)
              ))
            )
        ),
        best_match_per_result AS (
          -- If multiple rules match, select the one with highest priority
          SELECT DISTINCT ON (id_mesa, id_componente_plantilla_1, id_tipo_ensayo)
            *
          FROM evaluated_results
          ORDER BY id_mesa, id_componente_plantilla_1, id_tipo_ensayo, prioridad DESC
        ),
        mesa_test_counts AS (
          -- Count total tests and OK tests per mesa
          SELECT
            id_mesa,
            COUNT(*) as total_tests,
            COUNT(CASE WHEN resaltado = 'E5FAE1' THEN 1 END) as ok_tests
          FROM best_match_per_result
          GROUP BY id_mesa
        ),
        mesa_component_counts AS (
          -- Count total components per mesa (from plantilla)
          SELECT
            m.id_mesa,
            COUNT(DISTINCT pc.id_componente) as total_components
          FROM mesas m
          JOIN plantilla_componentes pc ON m.id_plantilla = pc.id_plantilla
          GROUP BY m.id_mesa
        ),
        altura_hinca_component_counts AS (
          -- Count components with "Altura hinca" (id_tipo_ensayo=2) test OK per mesa
          SELECT
            bmpr.id_mesa,
            COUNT(DISTINCT bmpr.id_componente_plantilla_1) as components_with_altura_hinca_ok
          FROM best_match_per_result bmpr
          WHERE bmpr.id_tipo_ensayo = 2
            AND bmpr.resaltado = 'E5FAE1'
          GROUP BY bmpr.id_mesa
        ),
        pot_test_counts AS (
          -- Count POT tests (id_tipo_ensayo=33) and OK POT tests per mesa
          SELECT
            bmpr.id_mesa,
            COUNT(*) as total_pot_tests,
            COUNT(CASE WHEN bmpr.resaltado = 'E5FAE1' THEN 1 END) as ok_pot_tests
          FROM best_match_per_result bmpr
          WHERE bmpr.id_tipo_ensayo = 33
          GROUP BY bmpr.id_mesa
        )
        -- Return only mesas where:
        -- 1. ALL tests are OK
        -- 2. ALL components have "Altura hinca" test with OK result
        -- 3. If POT tests exist, ALL must be OK (if no POT tests, it's OK)
        SELECT
          m.id_mesa,
          m.nombre_mesa,
          m.coord_x,
          m.coord_y,
          mp.dimension_x,
          mp.dimension_y,
          ct.nombre_ct,
          mp.nombre_plantilla,
          mtc.total_tests,
          mtc.ok_tests,
          mcc.total_components,
          COALESCE(ahcc.components_with_altura_hinca_ok, 0) as components_with_altura_hinca_ok,
          COALESCE(ptc.total_pot_tests, 0) as total_pot_tests,
          COALESCE(ptc.ok_pot_tests, 0) as ok_pot_tests
        FROM mesa_test_counts mtc
        INNER JOIN mesas m ON mtc.id_mesa = m.id_mesa
        LEFT JOIN cts ct ON m.id_ct = ct.id_ct
        LEFT JOIN mesa_plantillas mp ON m.id_plantilla = mp.id_plantilla
        INNER JOIN mesa_component_counts mcc ON m.id_mesa = mcc.id_mesa
        LEFT JOIN altura_hinca_component_counts ahcc ON m.id_mesa = ahcc.id_mesa
        LEFT JOIN pot_test_counts ptc ON m.id_mesa = ptc.id_mesa
        WHERE mtc.total_tests > 0
          AND mtc.total_tests = mtc.ok_tests  -- All existing tests are OK
          AND mcc.total_components = COALESCE(ahcc.components_with_altura_hinca_ok, 0)  -- All components have altura hinca OK
          AND (
            -- POT tests are optional: if they exist, all must be OK
            COALESCE(ptc.total_pot_tests, 0) = 0  -- No POT tests (OK)
            OR ptc.total_pot_tests = ptc.ok_pot_tests  -- All POT tests are OK
          )
        ORDER BY m.id_mesa
      `

      const result = await pool.query(query)
      console.log(`✅ Found ${result.rows.length} mesas with all tests OK, all components with Altura hinca OK, and POT tests OK (if any)`)
      return c.json(result.rows)
    } catch (error) {
      console.error('Error fetching mesas with all tests OK:', error)
      return c.json({ error: 'Failed to fetch mesas with all tests OK' }, 500)
    }
  })

  // Get mesa details by ID
  router.get('/api/mesas/:id', authMiddleware, async (c) => {
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
  router.get('/api/mesas/:id/components', authMiddleware, async (c) => {
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

  // Get full mesa data for printing reports
  router.get('/api/mesas/:id/full-report-data/:inspectionId', authMiddleware, async (c) => {
    const mesaId = c.req.param('id')
    const inspectionId = c.req.param('inspectionId')

    try {
      // Get mesa basic info
      const mesaQuery = `
        SELECT
          m.id_mesa,
          m.nombre_mesa,
          m.coord_x,
          m.coord_y,
          c.nombre_ct,
          mp.nombre_plantilla,
          mp.dimension_x,
          mp.dimension_y,
          mp.id_plantilla
        FROM mesas m
        JOIN cts c ON m.id_ct = c.id_ct
        JOIN mesa_plantillas mp ON m.id_plantilla = mp.id_plantilla
        WHERE m.id_mesa = $1
      `

      const mesaResult = await pool.query(mesaQuery, [mesaId])
      if (mesaResult.rows.length === 0) {
        return c.json({ error: 'Mesa not found' }, 404)
      }

      const mesa = mesaResult.rows[0]

      // Get plantilla components
      const componentsQuery = `
        SELECT
          id_componente,
          tipo_elemento,
          coord_x,
          coord_y,
          descripcion_punto_montaje,
          orden_prioridad
        FROM plantilla_componentes
        WHERE id_plantilla = $1
        ORDER BY orden_prioridad ASC, tipo_elemento, coord_x, coord_y
      `

      const componentsResult = await pool.query(componentsQuery, [mesa.id_plantilla])

      // Get all tipos ensayo
      const tiposEnsayoQuery = `
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
        ORDER BY grupo_ensayo, orden_prioridad ASC, nombre_ensayo
      `

      const tiposEnsayoResult = await pool.query(tiposEnsayoQuery)

      // Get test results for this mesa and inspection
      const resultsQuery = `
        SELECT
          re.id_tipo_ensayo,
          re.id_componente_plantilla_1,
          re.resultado_numerico,
          re.resultado_booleano,
          re.resultado_texto,
          re.comentario,
          re.fecha_medicion
        FROM resultados_ensayos re
        WHERE re.id_mesa = $1 AND re.id_inspeccion = $2
      `

      const resultsResult = await pool.query(resultsQuery, [mesaId, inspectionId])

      return c.json({
        ...mesa,
        components: componentsResult.rows,
        tiposEnsayo: tiposEnsayoResult.rows,
        results: resultsResult.rows
      })

    } catch (error) {
      console.error('Error fetching mesa full report data:', error)
      return c.json({ error: 'Failed to fetch mesa report data' }, 500)
    }
  })

  // Recalculate mesa dimensions based on components
  router.post('/api/recalculate-dimensions', async (c) => {
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

  return router
}
