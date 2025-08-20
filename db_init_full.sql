-- Script para la Creación de la Base de Datos para la Gestión de Ensayos
-- Adaptado para fvinspeccioneshincas (sin línea de conexión)

-- Crear tabla usuarios para integración con Keycloak
CREATE TABLE usuarios (
    id_usuario SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL,
    keycloak_id VARCHAR(100) NOT NULL UNIQUE,
    fecha_registro TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE usuarios IS 'Usuarios autenticados por Keycloak.';
COMMENT ON COLUMN usuarios.id_usuario IS 'Identificador único del usuario.';
COMMENT ON COLUMN usuarios.username IS 'Nombre de usuario.';
COMMENT ON COLUMN usuarios.email IS 'Correo electrónico.';
COMMENT ON COLUMN usuarios.keycloak_id IS 'ID de Keycloak.';
COMMENT ON COLUMN usuarios.fecha_registro IS 'Fecha de registro.';

-- 2.  CREACIÓN DE LAS TABLAS

-- TABLA: cts (Centros de Transformación)
CREATE TABLE cts (
    id_ct SERIAL PRIMARY KEY,
    nombre_ct VARCHAR(100) NOT NULL
);

COMMENT ON TABLE cts IS 'Tabla que almacena los centros de transformación.';
COMMENT ON COLUMN cts.id_ct IS 'Identificador único del centro de transformación.';
COMMENT ON COLUMN cts.nombre_ct IS 'Nombre del centro de transformación.';

-- TABLA: tipos_ensayo
CREATE TABLE tipos_ensayo (
    id_tipo SERIAL PRIMARY KEY,
    nombre_tipo VARCHAR(100) NOT NULL
);

COMMENT ON TABLE tipos_ensayo IS 'Tabla que almacena los tipos de ensayo.';
COMMENT ON COLUMN tipos_ensayo.id_tipo IS 'Identificador único del tipo de ensayo.';
COMMENT ON COLUMN tipos_ensayo.nombre_tipo IS 'Nombre del tipo de ensayo.';

-- TABLA: ensayos
CREATE TABLE ensayos (
    id_ensayo SERIAL PRIMARY KEY,
    id_tipo INT NOT NULL,
    id_ct INT NOT NULL,
    fecha_ensayo DATE NOT NULL,
    resultado VARCHAR(100),
    FOREIGN KEY (id_tipo) REFERENCES tipos_ensayo(id_tipo),
    FOREIGN KEY (id_ct) REFERENCES cts(id_ct)
);

COMMENT ON TABLE ensayos IS 'Tabla que almacena los ensayos realizados.';
COMMENT ON COLUMN ensayos.id_ensayo IS 'Identificador único del ensayo.';
COMMENT ON COLUMN ensayos.id_tipo IS 'Identificador del tipo de ensayo.';
COMMENT ON COLUMN ensayos.id_ct IS 'Identificador del centro de transformación.';
COMMENT ON COLUMN ensayos.fecha_ensayo IS 'Fecha en que se realizó el ensayo.';
COMMENT ON COLUMN ensayos.resultado IS 'Resultado del ensayo.';

-- TABLA: usuarios_ensayos (relación muchos a muchos entre usuarios y ensayos)
CREATE TABLE usuarios_ensayos (
    id_usuario INT NOT NULL,
    id_ensayo INT NOT NULL,
    PRIMARY KEY (id_usuario, id_ensayo),
    FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario),
    FOREIGN KEY (id_ensayo) REFERENCES ensayos(id_ensayo)
);

COMMENT ON TABLE usuarios_ensayos IS 'Tabla que relaciona usuarios con ensayos.';
COMMENT ON COLUMN usuarios_ensayos.id_usuario IS 'Identificador del usuario.';
COMMENT ON COLUMN usuarios_ensayos.id_ensayo IS 'Identificador del ensayo.';

-- TABLA: auditorias
CREATE TABLE auditorias (
    id_auditoria SERIAL PRIMARY KEY,
    id_ensayo INT NOT NULL,
    fecha_auditoria DATE NOT NULL,
    resultado VARCHAR(100),
    observaciones TEXT,
    FOREIGN KEY (id_ensayo) REFERENCES ensayos(id_ensayo)
);

COMMENT ON TABLE auditorias IS 'Tabla que almacena las auditorías realizadas a los ensayos.';
COMMENT ON COLUMN auditorias.id_auditoria IS 'Identificador único de la auditoría.';
COMMENT ON COLUMN auditorias.id_ensayo IS 'Identificador del ensayo auditado.';
COMMENT ON COLUMN auditorias.fecha_auditoria IS 'Fecha en que se realizó la auditoría.';
COMMENT ON COLUMN auditorias.resultado IS 'Resultado de la auditoría.';
COMMENT ON COLUMN auditorias.observaciones IS 'Observaciones adicionales de la auditoría.';

-- TABLA: acciones_mejora
CREATE TABLE acciones_mejora (
    id_accion SERIAL PRIMARY KEY,
    id_auditoria INT NOT NULL,
    descripcion TEXT NOT NULL,
    responsable VARCHAR(100),
    fecha_limite DATE,
    estado VARCHAR(50),
    FOREIGN KEY (id_auditoria) REFERENCES auditorias(id_auditoria)
);

COMMENT ON TABLE acciones_mejora IS 'Tabla que almacena las acciones de mejora derivadas de las auditorías.';
COMMENT ON COLUMN acciones_mejora.id_accion IS 'Identificador único de la acción de mejora.';
COMMENT ON COLUMN acciones_mejora.id_auditoria IS 'Identificador de la auditoría asociada.';
COMMENT ON COLUMN acciones_mejora.descripcion IS 'Descripción de la acción de mejora.';
COMMENT ON COLUMN acciones_mejora.responsable IS 'Responsable de implementar la acción de mejora.';
COMMENT ON COLUMN acciones_mejora.fecha_limite IS 'Fecha límite para implementar la acción de mejora.';
COMMENT ON COLUMN acciones_mejora.estado IS 'Estado de la acción de mejora (e.g., Pendiente, En Progreso, Completa).';

-- TABLA: documentos
CREATE TABLE documentos (
    id_documento SERIAL PRIMARY KEY,
    id_ensayo INT NOT NULL,
    nombre_documento VARCHAR(255) NOT NULL,
    tipo_documento VARCHAR(100),
    fecha_subida TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    ruta_archivo VARCHAR(255) NOT NULL,
    FOREIGN KEY (id_ensayo) REFERENCES ensayos(id_ensayo)
);

COMMENT ON TABLE documentos IS 'Tabla que almacena los documentos relacionados con los ensayos.';
COMMENT ON COLUMN documentos.id_documento IS 'Identificador único del documento.';
COMMENT ON COLUMN documentos.id_ensayo IS 'Identificador del ensayo asociado.';
COMMENT ON COLUMN documentos.nombre_documento IS 'Nombre del documento.';
COMMENT ON COLUMN documentos.tipo_documento IS 'Tipo de documento (e.g., PDF, DOCX).';
COMMENT ON COLUMN documentos.fecha_subida IS 'Fecha de subida del documento.';
COMMENT ON COLUMN documentos.ruta_archivo IS 'Ruta del archivo en el servidor.';
