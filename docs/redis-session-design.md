Externalizing session store to a KV store for server redundancy.

# Session Store Design (Fred Redis)

1. System Overview & Connection Configuration
- Goal: Replace in-memory session store with Redis via `fred` to support redundant BFF configurations.
- Client Type: `fred::clients::RedisPool` (Shared Client)
- Pool Strategy:
  - Use static `RedisPool`. (Alternatively, `DynamicPool` can be considered for high-volatility load scenarios.)
  - Initial size: 1
```rust
static REDIS_POOL: OnceLock<Pool> = OnceLock::new();

use fred::prelude::*;
let config = Config::from_url(redis_url)?;
let pool = Builder::from_config(config)
    .build_pool(1)?;
pool.init().await?;
```
- Timeouts       :
  * Connect Timeout : 100ms
  * Command Timeout : 50ms
  * Pool Wait       : None (No waiting since pool = 1)
  * Overall Session Budget : 80ms ~ 120ms
  * Verification: Align Redis server `timeout` with application settings.

2. Reconnection & Command Retry Policy
- Connection Reconnect: Enabled for background auto-recovery.
- Command Retry Policy: Generally disabled, except for critical operations.
  * General Commands : No retries.
  * Critical SET Operations : Max 2 retries if required.

3. Code Structure (Rust AppState)
- AppState: Stores `REDIS_POOL: OnceLock<fred::clients::Pool>`.
- Cloning Behavior: Thread-safe and internally reference-counted; low overhead.

4. Scalability & Clustering (Future-Proofing)
- Pool Tuning: Maintain `pool = 1` initially. Adjust based on performance profiling.
- Redis Cluster: Topology (Standalone vs. Cluster) is decoupled from application logic.

5. Network & Infrastructure Requirements
- Firewall: Allow bidirectional TCP traffic on Redis ports (e.g., 6379).
- Redis Server
  - Timeout Alignment: Ensure server-side timeout matches client configuration.
  - Memory Policy: Set `maxmemory-policy noeviction` to prevent session loss via LRU.

6. Local Development & Testing +To run a local Redis instance:
```bash
docker run -d --name redis -p 6379:6379 redis
```