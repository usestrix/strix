// Esquema MongoDB de Strix: colecciones, validadores ($jsonSchema) e índices.
//
// MongoDB no necesita esquema: las aplicaciones crean colecciones e índices al usarlas.
// Este script es para fijarlo de antemano (o documentarlo) y es idempotente: se puede
// ejecutar las veces que haga falta, sin perder datos.
//
//   mongosh "<MONGO_URI>" frontal/schema/mongo-init.js
//   MONGO_DB=strix MONGO_BUCKET=strix_runs SCHEMA_ACTION=warn mongosh "<MONGO_URI>" frontal/schema/mongo-init.js
//
// Variables: MONGO_DB (strix), MONGO_BUCKET (strix_runs), SCHEMA_ACTION ("error" rechaza
// los documentos inválidos; "warn" solo los anota en el log de Mongo).
//
// Lo ejecuta un usuario con dbAdmin sobre la base de datos (createCollection/collMod).
// A las aplicaciones les basta readWrite. Ejemplo de usuario de aplicación:
//   db.getSiblingDB("strix").createUser({user: "strix_app", pwd: "<pwd>", roles: [{role: "readWrite", db: "strix"}]})
//
// Colecciones:
//   <bucket>.files / <bucket>.chunks  ficheros de cada run (GridFS). Los escribe el orquestador
//                                     (k8s/kafka_orchestrator.py) y los lee el frontal
//                                     (frontal/app/artifacts.py).
//   scans                             un documento por escaneo del backend mínimo
//                                     (minimal_backend/app.py).

const dbName = process.env.MONGO_DB || "strix";
const bucket = process.env.MONGO_BUCKET || "strix_runs";
const action = process.env.SCHEMA_ACTION || "error";
const target = db.getSiblingDB(dbName);

const date = { bsonType: "date" };
const optionalString = { bsonType: ["string", "null"] };

const schemas = {
  [`${bucket}.files`]: {
    bsonType: "object",
    required: ["_id", "length", "chunkSize", "uploadDate", "filename", "metadata"],
    properties: {
      _id: { bsonType: "objectId" },
      length: { bsonType: ["int", "long"], minimum: 0 },
      chunkSize: { bsonType: ["int", "long"], minimum: 1 },
      uploadDate: date,
      // "<run>/<ruta relativa dentro del run>", p. ej. "juice-shop-3000_d898/run.json"
      filename: { bsonType: "string", pattern: "^[^/].*/.+" },
      metadata: {
        bsonType: "object",
        required: ["run"],
        properties: { run: { bsonType: "string", minLength: 1 } },
      },
    },
  },
  [`${bucket}.chunks`]: {
    bsonType: "object",
    required: ["_id", "files_id", "n", "data"],
    properties: {
      _id: { bsonType: "objectId" },
      files_id: { bsonType: "objectId" },
      n: { bsonType: ["int", "long"], minimum: 0 },
      data: { bsonType: "binData" },
    },
  },
  scans: {
    bsonType: "object",
    required: ["_id", "status", "created_at", "request"],
    properties: {
      _id: { bsonType: "string", pattern: "^minimal-" },
      status: { enum: ["queued", "running", "completed", "failed"] },
      created_at: date,
      started_at: date,
      ended_at: date,
      pod: optionalString,
      error: optionalString,
      // La petición tal cual se publicó en el topic de peticiones.
      request: {
        bsonType: "object",
        required: ["id", "target", "scan_mode"],
        properties: {
          id: { bsonType: "string" },
          target: { bsonType: "string", minLength: 1 },
          scan_mode: { enum: ["quick", "standard", "deep"] },
          instruction: { bsonType: "string" },
          max_budget: { bsonType: ["double", "int", "long"] },
          source: { bsonType: "string" },
        },
      },
      // Resumen del resultado de Strix (subconjunto del evento de resultado).
      result: {
        bsonType: "object",
        properties: {
          succeeded: { bsonType: "bool" },
          vulnerability_count: { bsonType: ["int", "long"] },
          vulnerabilities: { bsonType: "array" },
          error: optionalString,
        },
      },
    },
  },
};

const indexes = {
  // Los dos de GridFS son los que el driver crea por su cuenta; metadata.run es el de la app.
  [`${bucket}.files`]: [
    [{ filename: 1, uploadDate: 1 }, {}],
    [{ "metadata.run": 1 }, {}],
  ],
  [`${bucket}.chunks`]: [[{ files_id: 1, n: 1 }, { unique: true }]],
  scans: [
    [{ created_at: -1 }, {}],
    [{ status: 1 }, {}],
  ],
};

const existing = new Set(target.getCollectionNames());
for (const [name, schema] of Object.entries(schemas)) {
  const options = { validator: { $jsonSchema: schema }, validationLevel: "strict", validationAction: action };
  if (existing.has(name)) {
    target.runCommand({ collMod: name, ...options });
    print(`actualizada  ${dbName}.${name}`);
  } else {
    target.createCollection(name, options);
    print(`creada       ${dbName}.${name}`);
  }
  for (const [keys, opts] of indexes[name] || []) {
    target.getCollection(name).createIndex(keys, opts);
  }
}
print(`validación: ${action}`);
