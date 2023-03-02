# Database

Available databases:
* [mongo](#mongo)

## Mongo

> Only Mongo is supported, DocDB [does not support text index](https://docs.aws.amazon.com/documentdb/latest/developerguide/mongo-apis.html#mongo-apis-index) which is used in NVD's API to perform keyword search.

### Database & Collections
* `nvd`
  * `cve`: stores CVE records download from [CVE API](https://nvd.nist.gov/developers/vulnerabilities) and [CVE Data Feeds](https://nvd.nist.gov/vuln/data-feeds)
    * Unique key: CVE ID. E.g., `CVE-2022-0001`
  * `cpe`: stores CPE reocrds download from [CPE API](https://nvd.nist.gov/developers/products) and [CPE Data Feeds](https://nvd.nist.gov/products/cpe)
    * Unique key: CPE Name. E.g., `cpe:2.3:a:microsoft:office:2021:*:*:*:ltsc:*:x64:*`

### Initialization
Either create with [mongo-init.js](../service/test/mongo/mongo-init.js) directly or create through `inidb` command with `-db-type=mongo`

```bash
# build executable
$ go build -o bin/ ./db/...

# run command
$ ./bin/initdb -db-type mongo -db-endpoint <endpoint> -db-user <user> -db-pwd <pwd>
```

### Index
#### Index for matching CVE from CPE
* `nvd`
  * `cve`: index on `criteriaProductPrefix`, which is the prefix of CPE name which drop after product part.
    * E.g., `criteriaProductPrefix("cpe:2.3:a:microsoft:office:2021:*:*:*:ltsc:*:x64:*") = "cpe:2.3:a:microsoft:office"`

`criteriaProductPrefix` is generated from sources and write to `nvd.cve` when using `nvdetl` command. It is used to improve the performance when searching CVEs that contains CPE in their configuration since exactly match search is faster than prefix search.

```js
db.cve.createIndex({ "configurations.nodes.cpeMatch.criteriaProductPrefix": 1 }, { name: "cpeNameProductPrefix" });
```

#### Text indexs for NVD keyword search
* `nvd`
  * `cve`: `descriptions.value`
  * `cpe`: `titles.title` and `refs.ref`

```js
db.cve.createIndex({ "descriptions.value": "text" }, { name: "keyword" });
db.cpe.createIndex({ "titles.title": "text", "refs.ref": "text" }, { name: "keyword" });
```

### Additional preprocessing
To support query with `cpe match string` to get full CPEs. `nvdetl` command parsed cpe name to store each part seperately in `cpeNameParsed` to avoid using `regex` to match for performance.

* E.g., `cpe = "cpe:2.3:a:microsoft:office:2021:*:*:*:ltsc:*:x64:*"`, then the parsing result is as below
```json
{
    "cpeNameParsed": {
        "part": "a",
        "vendor": "microsoft",
        "product": "office",
        "version": "2021",
        "update": "*",
        "edition": "*",
        "lang": "*",
        "sw_edition": "ltsc",
        "target_sw": "*",
        "target_hw": "x64",
        "others": "*"
    }
}
```
