# go-nvd

NVD officially provides APIs for [CPE](https://nvd.nist.gov/developers/products) and [CVE](https://nvd.nist.gov/developers/vulnerabilities), while both are set with [rate limit](https://nvd.nist.gov/general/news/API-Key-Announcement).

To support high-volume query, `go-nvd` supports command to dump data from NVD to self-owned database and run API server on top of that to provide same API spec and part of parameters as NVD.

* Available database:
  * `mongo`

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

To try with docker, check [playground](#playground)

## Notice
There are some difference between go-nvd and offical nvd:
* Only support partial query parameters:
  * cve: `cveId`, `cpeName`, `keywordSearch`(`keywordExactMatch`),`resultsPerPage`(default:`2000`) and `startIndex`
  * cpe: `cpeName`, `cpeMatchString`, `keywordSearch`(`keywordExactMatch`),`resultsPerPage`(default:`10000`) and `startIndex`
* It's mandatory to provide one of the query in query string, while offical nvd api return all cve/cpe if not given.
  * cve: one of `cveId`, `cpeName`, `keywordSearch` should be given, else raising `400` error
  * cpe: one of `cpeName`, `cpeMatchString`, `keywordSearch` should be given, else raising `400` error
* Different logic to match the version of CPE, which might causing different results.
  * E.g., for `CVE-2003-0132`, it should be returned when query with version between `apache:http_server:2.0.0` and `apache:http_server:2.0.44`. However, should it match with partial version `apache:http_server:2.0`? NVD does not return while this repo regards `2.0` as `2.0.0` and `CVE-2003-0132` will be returned.
  > Actually, partial version should not be expected as valid input, whlie there are still softwares with version format: `<major>.<minor>` instead of `<major>.<minor>.<patch>`.

## DB
check [db.md](docs/db.md) for the details

## ETL
check [nvd.md](docs/nvd.md) for the details
* [`nvdetl`](docs/nvd.md#usage) for how to use command to dump data to database
* [ETL from the start](docs/nvd.md#etl-from-the-start) describes how to dump all the data with the correct order from NVD to database

## API
readiness endpoint: `nvd/v1/readiness`

### GET: `/nvd/v1/cve`
This API mimics the [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities), which implements the logic for `cveId`, `cpeName`, `keywordSearch`(`keywordExactMatch`),`resultsPerPage`(default:`2000`) and `startIndex` in query string, and the response is also the same.

To get CVEs by `cveId`, `cpeName` or `keywordSearch`(`keywordExactMatch`). E.g.,
* Query with `cveId = CVE-2006-3240` =>  `/nvd/v1/cve?cveId=CVE-2006-3240`
* Query with `cpeName = cpe:2.3:a:dotproject:dotproject:*:*:*:*:*:*:*:*` =>  `/nvd/v1/cve?cpeName=cpe:2.3:a:dotproject:dotproject:*:*:*:*:*:*:*:*`
* Query with `keywordSearch = Java Oracle` => `/nvd/v1/cve?keywordSearch=Java Oracle`
  * Query with `keywordExactMatch` => `/nvd/v1/cve?keywordSearch=Java Oracle&keywordExactMatch`

`200` found, which is same format as [NVD](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
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

`200` not found
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
This API mimics the [NVD CPE API](https://nvd.nist.gov/developers/products), which implements the logic for `cpeName`, `cpeMatchString`, `keywordSearch`(`keywordExactMatch`),`resultsPerPage`(default:`10000`) and `startIndex` in query string, and the response is also the same.

To get CPEs by `cpeName`, `cpeMatchString`, or `keywordSearch`(`keywordExactMatch`). E.g.,
* Query with `cpeName = cpe:2.3:a:dotproject:dotproject:*:*:*:*:*:*:*:*` =>  `/nvd/v1/cpe?cpeName=cpe:2.3:a:dotproject:dotproject:*:*:*:*:*:*:*:*`
* Query with `cpeMatchString = cpe:2.3:o:microsoft:windows_10` => `/nvd/v1/cpe?cpeMatchString=cpe:2.3:o:microsoft:windows_10`
* Query with `keywordSearch = Java Oracle` => `/nvd/v1/cpe?keywordSearch=Java Oracle`
  * Query with `keywordExactMatch` => `/nvd/v1/cpe?keywordSearch=Java Oracle&keywordExactMatch`

`200` found, which is same format as [NVD](https://csrc.nist.gov/schema/nvd/api/2.0/cpe_api_json_2.0.schema)
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

`200` not found
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
#### HTTP requests
* `http_request_total{api=...,code=...}` (counter) The amount of requests per HTTP status code
  * `api` includes
    * `/nvd/v1/cve`
    * `/nvd/v1/cpe`
* `http_request_duration_seconds` (histogram) A histogram of latencies for requests

#### Service
* `get_request_total{api=...,status=...}` (counter) The amount of requests to get scan report and status
  * `api` includes
    * `/cve`
    * `/cpe`
  * `status` includes
    * `found`
    * `not_found`
    * `error`

# Playground
### 1. build `nvd-tools` image
```bash
$ cd go-nvd
$ GOOS=linux go build -o service/build/bin/ ./...
$ cd service/build
$ docker build -t nvd-tools .
```

### 2. start with `mongo` as backend database
check [Endpoints](./docs/service.md#endpoints) for all the exposing ports.

#### `mongo`
```bash
$ cd service/test
$ docker-compose -f docker-compose-mongo.yaml up -d
```

### 3. try dumpping some data to database
check [Usage](./docs/nvd.md#usage) for the usage of `nvdetl` command
* `-apikey`: query NVD with API Key if given
* `-wait`: sleep seconds between each API request to NVD

#### `mongo`
```bash
# dump CVEs with lastModified between 2023-03-01 and 2023-03-02
$ docker run --rm --network go-nvd --entrypoint nvdetl nvd-tools -db-type mongo -db-user admin -db-pwd admin -db-endpoint mongo:27017 -sdate 2023-03-01 -edate 2023-03-02 -batch 100 -type cve

# dump CPEs with lastModified between 2023-03-01 and 2023-03-02
$ docker run --rm --network go-nvd --entrypoint nvdetl nvd-tools -db-type mongo -db-user admin -db-pwd admin -db-endpoint mongo:27017 -sdate 2023-03-01 -edate 2023-03-02 -batch 100 -type cpe
```

#### 4. try to query APIs and check the result
* CVE API
```bash
$ curl 'http://localhost:8080/nvd/v1/cve?cveId=CVE-2022-26579'
```

* CPE API
```bash
$ curl 'http://localhost:8080/nvd/v1/cpe?cpeName=cpe:2.3:a:luya:yii-helpers:1.0.0:*:*:*:*:*:*:*'
```
