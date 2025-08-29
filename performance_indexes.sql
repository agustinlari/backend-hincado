-- Índices para optimizar el rendimiento de la aplicación de inspecciones
-- Ejecutar estos índices para mejorar significativamente las consultas

-- Índice compuesto para resultados_ensayos por mesa y tipo de ensayo
CREATE INDEX IF NOT EXISTS idx_resultados_mesa_tipo_fecha 
ON resultados_ensayos (id_mesa, id_tipo_ensayo, fecha_medicion DESC, id_resultado DESC);

-- Índice compuesto para resultados_ensayos por componente y tipo de ensayo  
CREATE INDEX IF NOT EXISTS idx_resultados_componente_tipo_fecha 
ON resultados_ensayos (id_componente_plantilla_1, id_tipo_ensayo, fecha_medicion DESC, id_resultado DESC);

-- Índice para inspecciones por ID (si no existe ya)
CREATE INDEX IF NOT EXISTS idx_inspecciones_id ON inspecciones (id_inspeccion);

-- Índice para mesas por ID (si no existe ya) 
CREATE INDEX IF NOT EXISTS idx_mesas_id ON mesas (id_mesa);

-- Índice para tipos_ensayo por orden_prioridad
CREATE INDEX IF NOT EXISTS idx_tipos_ensayo_orden ON tipos_ensayo (orden_prioridad ASC);

-- Índice para plantilla_componentes por orden_prioridad
CREATE INDEX IF NOT EXISTS idx_componentes_orden ON plantilla_componentes (orden_prioridad ASC);

-- Índice compuesto para plantilla_componentes por plantilla y orden
CREATE INDEX IF NOT EXISTS idx_componentes_plantilla_orden 
ON plantilla_componentes (id_plantilla, orden_prioridad ASC);

-- Verificar que los índices se crearon correctamente
SELECT 
    schemaname,
    tablename,
    indexname,
    indexdef
FROM pg_indexes 
WHERE tablename IN ('resultados_ensayos', 'tipos_ensayo', 'plantilla_componentes', 'inspecciones', 'mesas')
ORDER BY tablename, indexname;