# Database

**Available databases:**
- [MongoDB](#mongo)

## MongoDB

> **Note:** Only MongoDB is supported. Amazon DocumentDB [does not support text indexes](https://docs.aws.amazon.com/documentdb/latest/developerguide/mongo-apis.html#mongo-apis-index), which are required for NVD's API keyword search functionality.

### Database & Collections

**Database:** `nvd`

- **`cve` collection**: Stores CVE records downloaded from the [CVE API](https://nvd.nist.gov/developers/vulnerabilities) and [CVE Data Feeds](https://nvd.nist.gov/vuln/data-feeds)
  - **Unique key:** CVE ID (e.g., `CVE-2022-0001`)

- **`cpe` collection**: Stores CPE records downloaded from the [CPE API](https://nvd.nist.gov/developers/products) and [CPE Data Feeds](https://nvd.nist.gov/products/cpe)
  - **Unique key:** CPE Name (e.g., `cpe:2.3:a:microsoft:office:2021:*:*:*:ltsc:*:x64:*`)

### Initialization

You can initialize the database using either of these methods:

1. **Direct initialization** with [mongo-init.js](../service/test/mongo/mongo-init.js)
2. **Command-line initialization** using the `initdb` command with `-db-type=mongo`

```bash
# Build executable
go build -o bin/ ./db/...

# Run initialization command
./bin/initdb -db-type mongo -db-endpoint <endpoint> -db-user <user> -db-pwd <pwd>
```

### Indexes

#### Index for Matching CVEs from CPEs

**Database:** `nvd`
- **`cve` collection**: Index on `criteriaProductPrefix`, which is the prefix of the CPE name that drops everything after the product part.
  - **Example:** `criteriaProductPrefix("cpe:2.3:a:microsoft:office:2021:*:*:*:ltsc:*:x64:*") = "cpe:2.3:a:microsoft:office"`

The `criteriaProductPrefix` is generated from sources and written to `nvd.cve` when using the `nvdetl` command. It improves performance when searching for CVEs that contain CPEs in their configuration, since exact match searches are faster than prefix searches.

```javascript
db.cve.createIndex({ "configurations.nodes.cpeMatch.criteriaProductPrefix": 1 }, { name: "cpeNameProductPrefix" });
```

#### Text Indexes for NVD Keyword Search

**Database:** `nvd`
- **`cve` collection**: Text index on `descriptions.value`
- **`cpe` collection**: Text index on `titles.title` and `refs.ref`

```javascript
db.cve.createIndex({ "descriptions.value": "text" }, { name: "keyword" });
db.cpe.createIndex({ "titles.title": "text", "refs.ref": "text" }, { name: "keyword" });
```

### Additional Preprocessing

To support queries with `cpe match string` to get full CPEs, the `nvdetl` command parses CPE names to store each part separately in `cpeNameParsed`. This avoids using regex for matching, which improves performance.

**Example:** For `cpe = "cpe:2.3:a:microsoft:office:2021:*:*:*:ltsc:*:x64:*"`, the parsing result is:
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
