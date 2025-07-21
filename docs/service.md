# Deployment

This document lists the environment variable options for the `server` to deploy to different environments, as well as how to test in a local environment.

## Environment Variables

Setting environment variables with the format `NVD_` + Upper($VAR) works the same as command-line arguments.

**Example:** Setting `NVD_LOGLVL` is equivalent to providing `-loglvl` as a command-line argument.

### Server Configuration

#### Logging
| Key             | Default | Description                                   |
|-----------------|---------|-----------------------------------------------|
| NVD_ACS_LOGLVL  | info    | Access logging level (debug/info/warn/error) |
| NVD_ERR_LOGLVL  | info    | Error logging level (debug/info/warn/error)  |

#### Service
| Key         | Default | Description                    |
|-------------|---------|--------------------------------|
| NVD_LISTEN  | :8080   | Listen address for API server  |
| NVD_METRIC  | :6060   | Metrics address for Prometheus |

#### Database (MongoDB)
| Key                 | Default | Description                                      |
|---------------------|---------|--------------------------------------------------|
| NVD_DB_TYPE         | mongo   | Database type (only MongoDB is supported)       |
| NVD_DB_USER         |         | Database username                                |
| NVD_DB_PWD          |         | Database password                               |
| NVD_DB_ENDPOINT     |         | Database endpoint                               |
| NVD_DB_TIMEOUT      | 5s      | Timeout for database operations                 |

## Build Images

```bash
cd go-nvd
GOOS=linux go build -o service/build/bin/ ./...
cd service/build
docker build -t nvd-tools .
```

## Testing

### Endpoints

**Database:** MongoDB

The [service](../service/) folder shows how to run in a local environment for testing:

- **[Test setup](../service/test/docker-compose-mongo.yaml)**: Runs MongoDB and `nvd-server` in containers
  - **API server**: `http://localhost:8080`
  - **API metrics**: `http://localhost:6060/metrics`
  - **MongoDB**: `http://localhost:27017`
  - **Mongo Express UI**: `http://localhost:8081`

### Start Containers

```bash
cd service/test
docker compose -f <yaml_path> up -d
```

### Check Server Readiness

```bash
curl 'http://localhost:8080/nvd/v1/readiness'
```
