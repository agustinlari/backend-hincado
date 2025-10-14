import { Hono } from 'hono'
import { Pool } from 'pg'

export function createDashboardRouter(pool: Pool, authMiddleware: any) {
  const router = new Hono()

  // Dashboard statistics endpoint
  router.get('/api/dashboard/estadisticas', authMiddleware, async (c) => {
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

      // Get temporal evolution (last 7 days with cumulative totals)
      const evolucionTemporalQuery = `
        WITH date_series AS (
          SELECT generate_series(
            CURRENT_DATE - INTERVAL '6 days',
            CURRENT_DATE,
            INTERVAL '1 day'
          )::date as fecha
        ),
        daily_counts AS (
          SELECT
            DATE(re.fecha_medicion) as fecha,
            COUNT(re.id_resultado) as cantidad_dia
          FROM resultados_ensayos re
          WHERE DATE(re.fecha_medicion) >= CURRENT_DATE - INTERVAL '6 days'
          GROUP BY DATE(re.fecha_medicion)
        ),
        cumulative_before_period AS (
          SELECT COUNT(*) as total_anterior
          FROM resultados_ensayos
          WHERE DATE(fecha_medicion) < CURRENT_DATE - INTERVAL '6 days'
        )
        SELECT
          ds.fecha,
          COALESCE(
            (SELECT total_anterior FROM cumulative_before_period) +
            (SELECT COALESCE(SUM(dc2.cantidad_dia), 0)
             FROM daily_counts dc2
             WHERE dc2.fecha <= ds.fecha),
            (SELECT total_anterior FROM cumulative_before_period)
          ) as cantidad_acumulada
        FROM date_series ds
        ORDER BY ds.fecha
      `
      const evolucionTemporalResult = await pool.query(evolucionTemporalQuery)
      const evolucionTemporal = evolucionTemporalResult.rows.map((row: any) => {
        const fecha = new Date(row.fecha)
        const dia = fecha.getDate().toString().padStart(2, '0')
        const mes = (fecha.getMonth() + 1).toString().padStart(2, '0')
        return {
          fecha: `${dia}/${mes}`, // Format as DD/MM
          cantidad: parseInt(row.cantidad_acumulada)
        }
      })

      // Get total components for "Sin medición" calculation
      const totalComponentesQuery = `
        SELECT COUNT(*) as total
        FROM mesas m
        JOIN plantilla_componentes pc ON m.id_plantilla = pc.id_plantilla
      `
      const totalComponentesResult = await pool.query(totalComponentesQuery)
      const totalComponentes = parseInt(totalComponentesResult.rows[0].total)

      // Get pie chart data for each HINCAS test type (only latest result per component)
      const pieChartsDataQuery = `
        WITH latest_results AS (
          SELECT
            re.id_tipo_ensayo,
            re.id_mesa,
            re.id_componente_plantilla_1,
            re.resultado_numerico,
            re.resultado_booleano,
            re.resultado_texto,
            ROW_NUMBER() OVER (
              PARTITION BY re.id_tipo_ensayo, re.id_mesa, re.id_componente_plantilla_1
              ORDER BY re.fecha_medicion DESC
            ) as rn
          FROM resultados_ensayos re
        )
        SELECT
          te.id_tipo_ensayo,
          te.nombre_ensayo,
          te.tipo_resultado,
          r.comentario as categoria,
          COUNT(lr.id_tipo_ensayo) as cantidad,
          CASE
            WHEN r.comentario = 'OK' THEN '#10b981'
            WHEN r.comentario = 'NOK' THEN '#F54927'
            ELSE '#6366f1'
          END as color
        FROM tipos_ensayo te
        LEFT JOIN reglas_resultados_ensayos r ON te.id_tipo_ensayo = r.id_tipo_ensayo
        LEFT JOIN latest_results lr ON (
          te.id_tipo_ensayo = lr.id_tipo_ensayo AND
          lr.rn = 1 AND
          (
            (r.valor_booleano IS NOT NULL AND lr.resultado_booleano = r.valor_booleano) OR
            (r.valor_numerico_1 IS NOT NULL AND (
              (r.tipo_condicion = '=' AND lr.resultado_numerico = r.valor_numerico_1) OR
              (r.tipo_condicion = '<>' AND lr.resultado_numerico != r.valor_numerico_1) OR
              (r.tipo_condicion = '>' AND lr.resultado_numerico > r.valor_numerico_1) OR
              (r.tipo_condicion = '<' AND lr.resultado_numerico < r.valor_numerico_1) OR
              (r.tipo_condicion = '>=' AND lr.resultado_numerico >= r.valor_numerico_1) OR
              (r.tipo_condicion = '<=' AND lr.resultado_numerico <= r.valor_numerico_1) OR
              (r.tipo_condicion = 'ENTRE' AND lr.resultado_numerico >= r.valor_numerico_1 AND lr.resultado_numerico <= r.valor_numerico_2) OR
              (r.tipo_condicion = 'FUERA_DE' AND (lr.resultado_numerico < r.valor_numerico_1 OR lr.resultado_numerico > r.valor_numerico_2))
            )) OR
            (r.valor_texto IS NOT NULL AND (
              (r.tipo_condicion = '=' AND lr.resultado_texto = r.valor_texto) OR
              (r.tipo_condicion = '<>' AND lr.resultado_texto != r.valor_texto)
            ))
          )
        )
        WHERE te.grupo_ensayo = 'HINCAS' AND r.comentario IN ('OK', 'NOK')
        GROUP BY te.id_tipo_ensayo, te.nombre_ensayo, te.tipo_resultado, r.comentario
        ORDER BY te.nombre_ensayo, r.comentario
      `
      const pieChartsResult = await pool.query(pieChartsDataQuery)

      // Group pie chart data by test type
      const pieChartsData: any = {}
      pieChartsResult.rows.forEach((row: any) => {
        if (!pieChartsData[row.id_tipo_ensayo]) {
          pieChartsData[row.id_tipo_ensayo] = {
            nombre_ensayo: row.nombre_ensayo,
            tipo_resultado: row.tipo_resultado,
            data: []
          }
        }
        pieChartsData[row.id_tipo_ensayo].data.push({
          categoria: row.categoria,
          cantidad: parseInt(row.cantidad),
          color: row.color
        })
      })

      // Add "Sin medición" category for each test type
      for (const tipoEnsayoId in pieChartsData) {
        const chartData = pieChartsData[tipoEnsayoId]

        // Count total measured for this specific test type (only latest results per component)
        const totalMedidosQuery = `
          SELECT COUNT(DISTINCT (id_mesa, id_componente_plantilla_1)) as total
          FROM (
            SELECT
              id_mesa,
              id_componente_plantilla_1,
              ROW_NUMBER() OVER (
                PARTITION BY id_tipo_ensayo, id_mesa, id_componente_plantilla_1
                ORDER BY fecha_medicion DESC
              ) as rn
            FROM resultados_ensayos
            WHERE id_tipo_ensayo = $1
          ) latest_only
          WHERE rn = 1
        `
        const totalMedidosResult = await pool.query(totalMedidosQuery, [tipoEnsayoId])
        const totalMedidos = parseInt(totalMedidosResult.rows[0].total)

        // Calculate "Sin medición" for this test type
        const sinMedicion = totalComponentes - totalMedidos

        if (sinMedicion > 0) {
          chartData.data.push({
            categoria: 'Sin medición',
            cantidad: sinMedicion,
            color: '#94a3b8'
          })
        }
      }

      const estadisticas = {
        totalEnsayos,
        ensayosFallidos,
        ensayosFallidosBooleanos,
        ensayosFallidosNumericos,
        ensayosFallidosTexto,
        totalEnsayosBooleanos,
        tasaExito,
        mesasInspeccionadas,
        evolucionTemporal,
        pieChartsData,
        totalComponentes
      }

      console.log('📈 Real dashboard statistics generated:', {
        ...estadisticas,
        pieChartsData: Object.keys(estadisticas.pieChartsData).length
      })
      return c.json(estadisticas)

    } catch (error) {
      console.error('Error fetching dashboard statistics:', error)
      return c.json({ error: 'Failed to fetch dashboard statistics' }, 500)
    }
  })

  return router
}
