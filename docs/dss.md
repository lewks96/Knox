#DSS - Distributed Session Store

Distributed session store is a mechanism for storing issues token artifacts in a distributed manner. This is useful for applications that are deployed in a distributed manner and need to share session state across multiple instances.
You have to pick a provider to use for the session store. Currently, we support `redis` and `memcache`. You do this by setting the `DSS_PROVIDER` environment variable to the provider you want to use.
At some point, DSS will be a standalone thing and the configuration will change.

### Configuration - memcache
| Property | Description | Default |
|----------|-------------|---------|
| DSS_MEMCACHE_PREALLOCATE | How many elements should be preallocated on launch | `1000` |
| DSS_CLEANUP_INTERVAL_SECONDS | How often to check for and clear expired sessions | `60` |

### Configuration - redis 
| Property | Description | Default |
|----------|-------------|---------|
| DSS_REDIS_HOST | The host of the redis server | `127.0.0.1` |
| DSS_REDIS_PORT | The port of the redis server | `6379` |
| DSS_REDIS_DB | The redis database to use | `0` |
| DSS_REDIS_PASSWORD | The password to use for the redis server | `""` |
| DSS_REDIS_USE_TLS | Whether to use TLS for the redis connection | `false` |


