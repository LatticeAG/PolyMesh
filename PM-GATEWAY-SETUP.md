Clone the polymesh-gateway repo, add the SPEC.md from polymesh, then seed it with a minimal scaffold so cursor-agent has something to work on. Run this:

```bash
cd /tmp
git clone https://github.com/LatticeAG/polymesh-gateway.git
cd polymesh-gateway

# Copy spec from polymesh
cp /home/ubuntu/polymesh/PM-GATEWAY-V1-SPEC.md ./SPEC.md

# Create basic scaffold
mkdir -p src/api src/do src/ws src/db migrations tests
cat > package.json << 'EOF'
{
  "name": "polymesh-gateway",
  "version": "1.0.0",
  "description": "CF Workers relay platform for agent meshes",
  "main": "src/index.ts",
  "scripts": {
    "dev": "wrangler dev",
    "deploy": "wrangler deploy",
    "test": "vitest run",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {},
  "devDependencies": {
    "@cloudflare/workers-types": "^4.20250401.0",
    "typescript": "^5.8.3",
    "vitest": "^3.2.4",
    "wrangler": "^4.0.0"
  }
}
EOF

cat > tsconfig.json << 'EOF'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "moduleResolution": "bundler",
    "lib": ["ES2022"],
    "types": ["@cloudflare/workers-types"],
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true,
    "outDir": "dist"
  },
  "include": ["src/**/*.ts"],
  "exclude": ["node_modules", "dist", "tests"]
}
EOF

cat > wrangler.toml << 'EOF'
name = "polymesh-gateway"
main = "src/index.ts"
compatibility_date = "2025-07-01"

[[d1_databases]]
binding = "PM_DB"
database_name = "pm-gateway"
database_id = ""

[[durable_objects.bindings]]
name = "MESH_DO"
class_name = "MeshDO"

[[migrations]]
tag = "v1"
new_classes = ["MeshDO"]
EOF

cat > migrations/001_init.sql << 'EOF'
CREATE TABLE IF NOT EXISTS meshes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  owner_agent_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  is_public INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  mesh_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  api_key_hash TEXT NOT NULL,
  capabilities TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at TEXT,
  FOREIGN KEY (mesh_id) REFERENCES meshes(id)
);

CREATE TABLE IF NOT EXISTS invites (
  code TEXT PRIMARY KEY,
  mesh_id TEXT NOT NULL,
  max_uses INTEGER DEFAULT 0,
  use_count INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT,
  FOREIGN KEY (mesh_id) REFERENCES meshes(id)
);

CREATE TABLE IF NOT EXISTS envelope_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mesh_id TEXT NOT NULL,
  from_agent TEXT NOT NULL,
  to_agent TEXT,
  capability TEXT NOT NULL,
  task_id TEXT,
  type TEXT NOT NULL,
  payload_size INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_agents_mesh ON agents(mesh_id);
CREATE INDEX IF NOT EXISTS idx_envelope_mesh ON envelope_log(mesh_id);
CREATE INDEX IF NOT EXISTS idx_envelope_task ON envelope_log(task_id);
EOF

# .gitignore
cat > .gitignore << 'EOF'
node_modules/
dist/
.env
*.log
wrangler.toml
EOF

npm install
git add -A
git commit -m "scaffold: polymesh-gateway v1 by LatticeAG"
git push origin main
```

Then run cursor-agent from the repo directory.
EOF