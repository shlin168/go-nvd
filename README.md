# go-nvd

[![Actions Status](https://github.com/shlin168/go-nvd/actions/workflows/go.yml/badge.svg)](https://github.com/shlin168/go-nvd/actions/workflows/go.yml)

NVD officially provides APIs for [CPE](https://nvd.nist.gov/developers/products) and [CVE](https://nvd.nist.gov/developers/vulnerabilities), both of which have [rate limits](https://nvd.nist.gov/general/news/API-Key-Announcement).

To support high-volume queries, `go-nvd` provides commands to dump data from NVD to a self-owned database and run an API server on top of it, providing the same API specification and partial parameters as NVD.

**Available databases:**
- MongoDB

```
                 API                    DB (nvd)
          ┌────────────────┐         ┌───────────┐
http      │ ┌────────────┐ │         │ ┌───────┐ │   nvdetl
req ———▶  │ │ (get) cve  │-│- - - —▶ │ │  cve  │ │  (command)  ┌───────┐
          │ └────────────┘ │         │ └───────┘ │ ◀────────── │  NVD  │
http      │ ┌────────────┐ │         │ ┌───────┐ │             └───────┘
rsp ◀───  │ │ (get) cpe  │-│- - - —▶ │ │  cpe  │ │
          │ └────────────┘ │         │ └───────┘ │
          └────────────────┘         └───────────┘

- - —▶ read
—————▶ write / data flow
```

To try with Docker, check the [playground](#playground) section.

## Notice

The `go-nvd` library has some distinct features compared to the official NVD API:

- **Only supports partial query parameters:**
  - **CVE**: `cveId`, `cpeName`, `keywordSearch` (`keywordExactMatch`), `resultsPerPage` (default: `2000`), and `startIndex`
  - **CPE**: `cpeName`, `cpeMatchString`, `keywordSearch` (`keywordExactMatch`), `resultsPerPage` (default: `10000`), and `startIndex`

- **Mandatory query parameters:** It's mandatory to provide at least one query parameter in the query string, while the official NVD API returns all CVEs/CPEs if none are given.
  - **CVE**: One of `cveId`, `cpeName`, or `keywordSearch` must be provided, otherwise a `400` error is raised
  - **CPE**: One of `cpeName`, `cpeMatchString`, or `keywordSearch` must be provided, otherwise a `400` error is raised

- **Different CPE version matching logic**, which might cause different results:
  - For example, `CVE-2003-0132` should be returned when querying with versions between `apache:http_server:2.0.0` and `apache:http_server:2.0.44`. However, should it match with partial version `apache:http_server:2.0`? NVD does not return it, while this repository treats `2.0` as `2.0.0` and returns `CVE-2003-0132`.

  > **Note:** Partial versions should not be expected as valid input, although there are still software packages with version format `<major>.<minor>` instead of `<major>.<minor>.<patch>`.

## Database

Check [db.md](docs/db.md) for details.

## ETL

Check [nvd.md](docs/nvd.md) for details:
- [`nvdetl`](docs/nvd.md#usage): How to use the command to dump data to the database
- [ETL from the start](docs/nvd.md#etl-from-the-start): How to dump all data in the correct order from NVD to the database

## API

**Readiness endpoint:** `nvd/v1/readiness`

### GET: `/nvd/v1/cve`

This API mimics the [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities), implementing the logic for `cveId`, `cpeName`, `keywordSearch` (`keywordExactMatch`), `resultsPerPage` (default: `2000`), and `startIndex` in the query string. The response format is identical to the official NVD API.

**Query examples:**
- Query by `cveId`: `/nvd/v1/cve?cveId=CVE-2006-3240`
- Query by `cpeName`: `/nvd/v1/cve?cpeName=cpe:2.3:a:dotproject:dotproject:*:*:*:*:*:*:*:*`
- Query by `keywordSearch`: `/nvd/v1/cve?keywordSearch=Java Oracle`
  - With exact match: `/nvd/v1/cve?keywordSearch=Java Oracle&keywordExactMatch`

**Response format (200 - Found):** Same format as [NVD](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
```json
{
  "resultsPerPage": 1,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2022-12-28T15:01:34.530",
  "vulnerabilities": [...],  // CVE list
}
```

**Response format (200 - Not Found):**
```json
{
  "resultsPerPage": 0,
  "startIndex": 0,
  "totalResults": 0,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2022-12-28T15:01:34.530",
  "vulnerabilities": [],  // CVE list
}
```

### GET: `/nvd/v1/cpe`

This API mimics the [NVD CPE API](https://nvd.nist.gov/developers/products), implementing the logic for `cpeName`, `cpeMatchString`, `keywordSearch` (`keywordExactMatch`), `resultsPerPage` (default: `10000`), and `startIndex` in the query string. The response format is identical to the official NVD API.

**Query examples:**
- Query by `cpeName`: `/nvd/v1/cpe?cpeName=cpe:2.3:a:dotproject:dotproject:*:*:*:*:*:*:*:*`
- Query by `cpeMatchString`: `/nvd/v1/cpe?cpeMatchString=cpe:2.3:o:microsoft:windows_10`
- Query by `keywordSearch`: `/nvd/v1/cpe?keywordSearch=Java Oracle`
  - With exact match: `/nvd/v1/cpe?keywordSearch=Java Oracle&keywordExactMatch`

**Response format (200 - Found):** Same format as [NVD](https://csrc.nist.gov/schema/nvd/api/2.0/cpe_api_json_2.0.schema)
```json
{
  "resultsPerPage": 1,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CPE",
  "version": "2.0",
  "timestamp": "2022-12-28T15:01:34.530",
  "products": [...],  // CPE list
}
```

**Response format (200 - Not Found):**
```json
{
  "resultsPerPage": 0,
  "startIndex": 0,
  "totalResults": 0,
  "format": "NVD_CPE",
  "version": "2.0",
  "timestamp": "2022-12-28T15:01:34.530",
  "products": [],  // CPE list
}
```

## Metrics

### Server

#### HTTP Requests
- `http_request_total{api=...,code=...}` (counter): The number of requests per HTTP status code
  - `api` includes:
    - `/nvd/v1/cve`
    - `/nvd/v1/cpe`
- `http_request_duration_seconds` (histogram): A histogram of request latencies

#### Service
- `get_request_total{api=...,status=...}` (counter): The number of requests to get scan reports and status
  - `api` includes:
    - `/cve`
    - `/cpe`
  - `status` includes:
    - `found`
    - `not_found`
    - `error`

# Playground

### 1. Build `nvd-tools` Image
```bash
cd go-nvd
GOOS=linux go build -o service/build/bin/ ./...
cd service/build
docker build -t nvd-tools .
```

### 2. Start with MongoDB as Backend Database
Check [Endpoints](./docs/service.md#endpoints) for all exposed ports.

#### MongoDB
```bash
cd service/test
docker-compose -f docker-compose-mongo.yaml up -d
```

### 3. Dump Sample Data to Database
Check [Usage](./docs/nvd.md#usage) for the usage of the `nvdetl` command:
- `-apikey`: Query NVD with API key if provided
- `-wait`: Sleep duration between each API request to NVD

#### MongoDB
```bash
# Dump CVEs with lastModified between 2023-03-01 and 2023-03-02
docker run --rm --network go-nvd --entrypoint nvdetl nvd-tools \
  -db-type mongo -db-user admin -db-pwd admin -db-endpoint mongo:27017 \
  -sdate 2023-03-01 -edate 2023-03-02 -batch 100 -type cve

# Dump CPEs with lastModified between 2023-03-01 and 2023-03-02
docker run --rm --network go-nvd --entrypoint nvdetl nvd-tools \
  -db-type mongo -db-user admin -db-pwd admin -db-endpoint mongo:27017 \
  -sdate 2023-03-01 -edate 2023-03-02 -batch 100 -type cpe
```

### 4. Test API Endpoints

#### CVE API
```bash
curl 'http://localhost:8080/nvd/v1/cve?cveId=CVE-2022-26579'
```

#### CPE API
```bash
curl 'http://localhost:8080/nvd/v1/cpe?cpeName=cpe:2.3:a:luya:yii-helpers:1.0.0:*:*:*:*:*:*:*'
```
