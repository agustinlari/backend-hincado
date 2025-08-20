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

-- TABLA: ensayos (Ensayos de laboratorio)
CREATE TABLE ensayos (
    id_ensayo SERIAL PRIMARY KEY,
    nombre_ensayo VARCHAR(100) NOT NULL,
    fecha_ensayo DATE NOT NULL,
    resultado VARCHAR(50),
    id_ct SERIAL REFERENCES cts(id_ct) ON DELETE CASCADE
);

COMMENT ON TABLE ensayos IS 'Tabla que almacena los ensayos de laboratorio realizados.';
COMMENT ON COLUMN ensayos.id_ensayo IS 'Identificador único del ensayo.';
COMMENT ON COLUMN ensayos.nombre_ensayo IS 'Nombre del ensayo.';
COMMENT ON COLUMN ensayos.fecha_ensayo IS 'Fecha en que se realizó el ensayo.';
COMMENT ON COLUMN ensayos.resultado IS 'Resultado del ensayo.';
COMMENT ON COLUMN ensayos.id_ct IS 'Identificador del centro de transformación donde se realizó el ensayo.';

-- TABLA: usuarios_ct (Relación usuarios - centros de transformación)
CREATE TABLE usuarios_ct (
    id_usuario SERIAL REFERENCES usuarios(id_usuario) ON DELETE CASCADE,
    id_ct SERIAL REFERENCES cts(id_ct) ON DELETE CASCADE,
    rol VARCHAR(50),
    PRIMARY KEY (id_usuario, id_ct)
);

COMMENT ON TABLE usuarios_ct IS 'Tabla que relaciona usuarios con centros de transformación.';
COMMENT ON COLUMN usuarios_ct.id_usuario IS 'Identificador del usuario.';
COMMENT ON COLUMN usuarios_ct.id_ct IS 'Identificador del centro de transformación.';
COMMENT ON COLUMN usuarios_ct.rol IS 'Rol del usuario en el centro de transformación.';
