# NVD (U.S. National Vulnerability Database)

CVE and NVD are two separate programs:
- **CVE List**: Launched by MITRE in 1999
- **NVD**: Launched by NIST (National Institute of Standards and Technology) in 2005

> **[Relationship](https://cve.mitre.org/about/cve_and_nvd_relationship.html):** The CVE List feeds NVD, which then builds upon the information included in CVE Records to provide enhanced information for each record such as fix information, severity scores, and impact ratings. As part of its enhanced information, NVD also provides advanced searching features such as by OS; by vendor name, product name, and/or version number; and by vulnerability type, severity, related exploit range, and impact.

NVD provides the following data sources:
- **[CVE API](https://nvd.nist.gov/developers/vulnerabilities)**
- **[CVE Data Feeds](https://nvd.nist.gov/vuln/data-feeds)**: Actually from MITRE, deprecated around December 2023 (actual date may vary)
- **[CPE API](https://nvd.nist.gov/developers/products)**
- **[CPE Data Feeds](https://nvd.nist.gov/products/cpe)**: Actually from MITRE, deprecated around December 2023 (actual date may vary)

NVD officially recommends users to use the APIs instead of Data Feeds. However, the APIs have strict [rate limits](https://nvd.nist.gov/general/news/API-Key-Announcement), which makes them unsuitable for high-volume queries.

## ETL (Extract, Transform, Load)

To overcome NVD's API rate limits, we leverage the `lastModStartDate` and `lastModEndDate` parameters to retrieve CPEs and CVEs that have been modified within specific time ranges, then periodically upsert them to the database. For data earlier than 2008, we download from [CVE Data Feeds](https://nvd.nist.gov/vuln/data-feeds) and [CPE Data Feeds](https://nvd.nist.gov/products/cpe), converting the format from MITRE to NVD (though some differences remain since NVD typically contains more information).

### Build

To build the `nvdetl` executable:
```bash
go build -o bin/ ./nvd/...
```

### Usage

To dump data from NVD, first use [`initdb`](../db/cmd/initdb/main.go) to initialize the environment. Check the [Database](#database) section for details.

#### CVE

**Download from [Data Feeds](https://nvd.nist.gov/vuln/data-feeds) and upsert to database:**
- `-data`: Data path to import, supports local or web paths starting with `http`. If it's not a local path, `nvdetl` downloads and extracts the file, storing temporary files in `/tmp/`.

```bash
./bin/nvdetl -type cve -db-user <user> -db-pwd <pwd> -db-endpoint <dbendpoint> \
  -data https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2022.json.gz
```

**Get data from [API](https://nvd.nist.gov/developers/vulnerabilities) and upsert to database:**
- `-sdate`: Converted to the `lastModStartDate` query parameter
- `-edate`: Converted to the `lastModEndDate` query parameter
- `-wait` (default: `5s`): Sleep duration between each request to NVD to avoid rate limits
- `-apikey`: API key for NVD (optional)
- `-batch` (default: `1`): Batch size for upserting data to database
- `-timeout` (default: `1m`): Timeout for each API request to NVD

```bash
./bin/nvdetl -type cve -db-user <user> -db-pwd <pwd> -db-endpoint <dbendpoint> \
  -sdate 2022-12-01 -edate 2023-01-01 [-wait 10s -batch 10]
```

#### CPE

**Download from [Data Feeds](https://nvd.nist.gov/products/cpe) and upsert to database:**
- `-data`: Data path to import, supports local or web paths starting with `http`. If it's not a local path, `nvdetl` downloads and extracts the file, storing temporary files in `/tmp/`.

```bash
./bin/nvdetl -type cpe -db-user <user> -db-pwd <pwd> -db-endpoint <dbendpoint> \
  -data https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz
```

**Get data from [API](https://nvd.nist.gov/developers/products) and upsert to database:**
- `-sdate`: Converted to the `lastModStartDate` query parameter
- `-edate`: Converted to the `lastModEndDate` query parameter
- `-wait` (default: `5s`): Sleep duration between each request to NVD to avoid rate limits
- `-apikey`: API key for NVD (optional)
- `-batch` (default: `1`): Batch size for upserting data to database
- `-timeout` (default: `1m`): Timeout for each API request to NVD

```bash
./bin/nvdetl -type cpe -db-user <user> -db-pwd <pwd> -db-endpoint <dbendpoint> \
  -sdate 2022-12-01 -edate 2023-01-01 [-wait 10s -batch 10]
```

## Database

### MongoDB

**Database:** `nvd`

**Collections:**
- **`cve` collection**:
  - Index: `cveId` (unique) - e.g., `CVE-2002-0392`
  - Index: `cpeName` - e.g., `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
  - Index: `cpeNameProductPrefix` - e.g., `cpe:2.3:a:apache:http_server`
  - Index (text): `keyword`, generated from `descriptions.value`

- **`cpe` collection**:
  - Index: `cpeName` - e.g., `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
  - Index (text): `keyword`, generated from `titles.title` and `refs.ref`

**Index generation scripts:**
- [mongo-init.js](../service/test/mongo/mongo-init.js)
- [`initdb`](../db/cmd/initdb/main.go) with `-db-type=mongo` also creates collections and indexes

### Data Structure

- **`cve` collection records**: Contains the `cve` field from items in the `vulnerabilities` field from [NVD's CVE API](https://nvd.nist.gov/developers/vulnerabilities) responses and [Data Feeds](https://nvd.nist.gov/vuln/data-feeds)
- **`cpe` collection records**: Contains the `cpe` field from items in the `products` field from [NVD's CPE API](https://nvd.nist.gov/developers/products) responses and [Data Feeds](https://nvd.nist.gov/products/cpe)

### Upsert Logic

#### CVE Records

Since `cveId` is set as a unique index, every record retrieved from the source is checked against existing records with the same `cveId` in the collection:

- **If no matching `cveId` exists**: Insert the new record
- **If a record with the same `cveId` exists**: Check the `lastModified` timestamp
  - If the incoming record has a newer or equal `lastModified` timestamp: Replace the existing record
  - If the existing record has a newer `lastModified` timestamp: Skip with logging

**Note about timestamp formats:**
- **MITRE** format: `2023-01-01T00:20:20`
- **NVD** format: `2023-01-01T00:20:20.168`

When converting data from MITRE to NVD format, we can only append `.000` to the MITRE timestamp, so the `lastModified` values stored in the database differ even though they represent the same record:
- **MITRE**: `2023-01-01T00:20:20.000`
- **NVD**: `2023-01-01T00:20:20.168`

**Data source priority:** We prioritize data from NVD. Since `lastModified` in NVD is always `>=` `lastModified` in MITRE when representing the same CVE modification event, the upsert logic (**always use the latest `lastModified`**) works automatically without needing to differentiate sources.

**Edge case:** There's a small chance that both sources contain the same `lastModified` timestamp (when the NVD timestamp ends with `.000`). If MITRE data is imported after NVD data in this case, MITRE will replace the existing NVD record. However, MITRE data import is expected to run only once initially to fill historical CVEs not provided by NVD. All subsequent data should come from NVD.

### ETL from Scratch

To dump all CVEs to the database:

1. **[One-time]** Dump from MITRE (2002 - 2008 or later)
2. **[One-time]** Dump from NVD (2008 - current year)
3. **[Scheduled]** Continuously dump from NVD to stay current with the latest information

#### Scripts

The following sample script downloads all CVEs from 1999-2022 (steps 1 and 2):

**Configuration notes:**
- Modify the ending year if needed (currently `2022`)
- Fill in the values for `-db-endpoint`, `-db-user`, `-db-pwd`
- Increase `-db-timeout` if you encounter `upsert cve err: context deadline exceeded`
  - **Note:** Importing MITRE data feeds for 2021 requires significant resources
- `interval`: Month range for querying the NVD API. Since the maximum allowable range is 120 consecutive days per NVD API documentation, `interval` should be less than `4`
  - **4 months** might return a `404` response from NVD as it may exceed 120 days; we recommend setting this value to `3` or less
- `-wait`: Time duration between each NVD API request, since NVD has strict rate limits (they recommend querying once every `6s`)
- `sleep 10`: Also used to avoid NVD rate limits
- `-batch`: Batch size when upserting data to the database

**CVE ETL Script**

*Change the path of the `nvdetl` executable if needed.*

```bash
set -e

# 1. Import from MITRE data feed (run before dumping from NVD Vulnerability CVE API)
# Source: https://nvd.nist.gov/vuln/data-feeds
for i in {2002..2022}; do
    url=https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$i.json.gz
    ./nvdetl -type cve -db-endpoint <db endpoint> -db-user <db user> -db-pwd <db password> \
             -data $url -db-timeout 5m -batch 100
done

# 2. Import from NVD Vulnerability CVE API
# Source: https://nvd.nist.gov/developers/vulnerabilities

# Interval is the range of months to query from NVD each time (modify if needed)
# Example: interval=3 queries NVD with 3 months each time:
# 1. sdate: 2008-01-01 -> edate: 2008-04-01
# 2. sdate: 2008-04-01 -> edate: 2008-07-01
# 3. ...
interval=3

# Calculate execution count based on interval
# Example: interval=3 means nvdetl needs to run 12/3 = 4 times per year
times=$((12 / interval))

for i in {2008..2022}; do
    for ((j=0; j<$times; j++)); do
        m=$(printf %02d $(($j*$interval+1)))
        
        sdate=$i-$m-01
        edate=$(date -d "$sdate+$interval month" +%Y-%m-%d)
        
        ./nvdetl -type cve -db-endpoint <db endpoint> -db-user <db user> -db-pwd <db password> \
                 -sdate $sdate -edate $edate -wait 10s -batch 100
        
        sleep 10
    done
done
```

**CPE ETL Script**

*Change the path of the `nvdetl` executable if needed.*

```bash
set -e

# 1. Import from MITRE data feed (run before dumping from NVD CPE Dictionary)
# Source: https://nvd.nist.gov/products/cpe
url=https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz
./nvdetl -type cpe -db-endpoint <db endpoint> -db-user <db user> -db-pwd <db password> \
         -data $url -db-timeout 5m -batch 100

# 2. Import from NVD Vulnerability CPE API
# Source: https://nvd.nist.gov/developers/products

# Interval is the range of months to query from NVD each time (modify if needed)
# Example: interval=3 queries NVD with 3 months each time:
# 1. sdate: 2008-01-01 -> edate: 2008-04-01
# 2. sdate: 2008-04-01 -> edate: 2008-07-01
# 3. ...
interval=3

# Calculate execution count based on interval
# Example: interval=3 means nvdetl needs to run 12/3 = 4 times per year
times=$((12 / interval))

for i in {2008..2022}; do
    for ((j=0; j<$times; j++)); do
        m=$(printf %02d $(($j*$interval+1)))
        
        sdate=$i-$m-01
        edate=$(date -d "$sdate+$interval month" +%Y-%m-%d)
        
        ./nvdetl -type cpe -db-endpoint <db endpoint> -db-user <db user> -db-pwd <db password> \
                 -sdate $sdate -edate $edate -wait 10s -batch 100
        
        sleep 10
    done
done
```
