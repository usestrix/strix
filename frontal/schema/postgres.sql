-- Esquema PostgreSQL del backend del frontal de Strix.
-- GENERADO desde frontal/app/models.py con frontal/schema/generate_postgres_sql.py:
-- no editar a mano.
--
-- El backend crea estas tablas solo al arrancar si su usuario tiene permiso de CREATE.
-- Si no lo tiene, ejecutar este fichero UNA vez, como propietario de la base de datos:
--
--   psql "<URL del propietario>" -v ON_ERROR_STOP=1 -f postgres.sql
--
-- Va en una transacción: si algo falla (p. ej. las tablas ya existen) no cambia nada.
-- Después, conceder al usuario de la aplicación solo DML:
--
--   GRANT USAGE ON SCHEMA public TO <usuario_app>;
--   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO <usuario_app>;
--   GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO <usuario_app>;
--
-- Con las tablas ya creadas, el arranque no ejecuta ningún DDL.

BEGIN;

CREATE TABLE apps (
	id BIGSERIAL NOT NULL,
	name VARCHAR(200) NOT NULL,
	target TEXT NOT NULL,
	environment VARCHAR(50),
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (name)
);

CREATE TABLE scans (
	id BIGSERIAL NOT NULL,
	app_id BIGINT NOT NULL,
	kind VARCHAR(20) NOT NULL,
	status VARCHAR(20) NOT NULL,
	scan_mode VARCHAR(20) NOT NULL,
	target TEXT,
	max_budget FLOAT,
	scope_mode VARCHAR(20),
	request_id VARCHAR(200),
	request_payload JSONB,
	result JSONB,
	run_name VARCHAR(200),
	instruction TEXT,
	parent_scan_id BIGINT,
	retest_finding_ids JSONB,
	started_at TIMESTAMP WITH TIME ZONE,
	ended_at TIMESTAMP WITH TIME ZONE,
	llm_usage JSONB,
	artifact_path TEXT,
	error TEXT,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(app_id) REFERENCES apps (id) ON DELETE CASCADE,
	FOREIGN KEY(parent_scan_id) REFERENCES scans (id) ON DELETE SET NULL
);

CREATE INDEX ix_scans_app_id ON scans (app_id);
CREATE INDEX ix_scans_request_id ON scans (request_id);
CREATE INDEX ix_scans_status ON scans (status);

CREATE TABLE findings (
	id BIGSERIAL NOT NULL,
	app_id BIGINT NOT NULL,
	fingerprint VARCHAR(64) NOT NULL,
	title TEXT NOT NULL,
	severity VARCHAR(20) NOT NULL,
	cvss FLOAT,
	cwe VARCHAR(30),
	endpoint TEXT,
	method VARCHAR(10),
	status VARCHAR(20) NOT NULL,
	first_seen_scan_id BIGINT,
	last_seen_scan_id BIGINT,
	last_retest_scan_id BIGINT,
	last_verdict VARCHAR(20),
	triage VARCHAR(20),
	data JSONB NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_findings_app_fingerprint UNIQUE (app_id, fingerprint),
	FOREIGN KEY(app_id) REFERENCES apps (id) ON DELETE CASCADE,
	FOREIGN KEY(first_seen_scan_id) REFERENCES scans (id) ON DELETE SET NULL,
	FOREIGN KEY(last_seen_scan_id) REFERENCES scans (id) ON DELETE SET NULL,
	FOREIGN KEY(last_retest_scan_id) REFERENCES scans (id) ON DELETE SET NULL
);

CREATE INDEX ix_findings_app_status ON findings (app_id, status);
CREATE INDEX ix_findings_severity ON findings (severity);

CREATE TABLE finding_observations (
	id BIGSERIAL NOT NULL,
	finding_id BIGINT NOT NULL,
	scan_id BIGINT NOT NULL,
	vuln_id VARCHAR(50),
	verdict VARCHAR(20) NOT NULL,
	confidence VARCHAR(20),
	evidence TEXT,
	raw JSONB NOT NULL,
	observed_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_observation_finding_scan UNIQUE (finding_id, scan_id),
	FOREIGN KEY(finding_id) REFERENCES findings (id) ON DELETE CASCADE,
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX ix_finding_observations_scan_id ON finding_observations (scan_id);

CREATE TABLE finding_triage (
	id BIGSERIAL NOT NULL,
	finding_id BIGINT NOT NULL,
	decision VARCHAR(20) NOT NULL,
	justification TEXT,
	author VARCHAR(200),
	scan_id BIGINT,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(finding_id) REFERENCES findings (id) ON DELETE CASCADE,
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE SET NULL
);

CREATE INDEX ix_finding_triage_finding_id ON finding_triage (finding_id);

COMMIT;
