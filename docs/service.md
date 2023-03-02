# Deployment

The document list the environment variable options for `server` to deploy to the environment. Also how to test in the local environment.

## Environment Variables

Setting env variables with format: `NVD_` + Upper($VAR) works the same as argvs
* E.g., setting `NVD_LOGLVL` is the same as given `-loglvl`

### Server
#### Log
| Key             | Default | Description                                  |
|-----------------|---------|----------------------------------------------|
| NVD_ACS_LOGLVL  | info    | Access logging level - debug/info/warn/error |
| NVD_ERR_LOGLVL  | info    | Error logging level - debug/info/warn/error  |

#### Service
| Key         | Default | Description                   |
|-------------|---------|-------------------------------|
| NVD_LISTEN  | :8080   | Listen address of API server  |
| NVD_METRIC  | :6060   | Metric address of Prometheus  |

#### DB (Mongo)
| Key                 | Default | Description                                     |
|---------------------|---------|-------------------------------------------------|
| NVD_DB_TYPE         | mongo   | DB type (only support mongo so far)             |
| NVD_DB_USER         |         | User name for DB                                |
| NVD_DB_PWD          |         | User password for DB                            |
| NVD_DB_ENDPOINT     |         | DB Endpoint                                     |
| NVD_DB_TIMEOUT      | 5s      | Timeout of operation to DB                      |

# Build images
```bash
$ cd go-nvd
$ GOOS=linux go build -o service/build/bin/ ./...
$ cd service/build
$ docker build -t nvd-tools .
```

# Test
## Endpoints
DB: `mongo`
[Service](../service/) folder shows how to run in local environment for testing
  * [test](../service/test/docker-compose-mongo.yaml): run `mongo` and `nvd-server` in containers.
    * API: `http://localhost:8080`
    * API metrics: `http://localhost:6060/metrics`
    * mongo: `http://localhost:27017`
    * mongo express: `http://localhost:8081`

## Start containers
```bash
$ cd service/test
$ docker compose -f <yaml_path> up -d
```

Check readiness endpoint for server
```bash
$ curl 'http://localhost:8080/nvd/readiness'
```
