# NVD (U.S. National Vulnerability Database)

CVE and NVD are two seperate programs
* CVE List was launched by MITRE in 1999
* NVD was launched by NIST(National Institute of Standards and Technology) in 2005

> [Relationship](https://cve.mitre.org/about/cve_and_nvd_relationship.html) – The CVE List feeds NVD, which then builds upon the information included in CVE Records to provide enhanced information for each record such as fix information, severity scores, and impact ratings. As part of its enhanced information, NVD also provides advanced searching features such as by OS; by vendor name, product name, and/or version number; and by vulnerability type, severity, related exploit range, and impact.

In NVD, they provide
* [CVE API](https://nvd.nist.gov/developers/vulnerabilities)
* [CVE Data Feeds](https://nvd.nist.gov/vuln/data-feeds): actually from Mitre, and will be deprecated around Dec in 2023 (the actual deprecated date might be changed).
* [CPE API](https://nvd.nist.gov/developers/products)
* [CPE Data Feeds](https://nvd.nist.gov/products/cpe): actually from Mitre, and will be deprecated around Dec in 2023 (the actual deprecated date might be changed).

NVD officially recommands users to use the API instead of Data Feeds, while the API has strict [rate limit](https://nvd.nist.gov/general/news/API-Key-Announcement), which is not suitable if there's a need to query with high-volume.

## ETL (`cpe` and `cve`)
To overcome the API limit from NVD, we leverage the parameter `lastModStartDate` and `lastModEndDate` of APIs to get CPEs and CVEs that has been modified in certain time range, and periodically upsert them to the database. For the data that is earlier than `2008`, we download from [CVE Data Feeds](https://nvd.nist.gov/vuln/data-feeds) and [CPE DataFeeds](https://nvd.nist.gov/products/cpe), transfer the format from `mitre` to `nvd` (while there are still some differences since `nvd` mostly contains more information)

### Build
* To build the `nvdetl` executable
```bash
$ go build -o bin/ ./nvd/...
```

### Usage

To dump data from NVD, use [`initdb`](../db/cmd/initdb/main.go) to initialize environment first, check [Database](#database) for the details.

#### CVE
* To download from [Data Feeds](https://nvd.nist.gov/vuln/data-feeds) and upsert to database
  * `-data`: data path to import, support local or web path which starts with `http`. If it's not local path, `nvdetl` download and untar the file, the temp file is in `/tmp/`.

```bash
./bin/nvdetl -type cve -db-user <user> -db-pwd <pwd> -db-endpoint <dbendpoint> -data https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2022.json.gz
```

* To get data from [API](https://nvd.nist.gov/developers/vulnerabilities) and upsert to database
  * `-sdate`: converted to value of `lastModStartDate` key in query string
  * `-edate`: converted to value of `lastModEndDate` key in query string
  * `-wait`(default: `5s`): which is the seconds to sleep between each request to NVD to avoid rate limit
  * `-apikey`: API key for NVD, it's optional
  * `-batch`(default: `1`): batch size to upsert data to database
  * `-timeout`(default: `1m`): timeout for each API request to NVD

```bash
./bin/nvdetl -type cve -db-user <user> -db-pwd <pwd> -db-endpoint <dbendpoint> -sdate 2022-12-01 -edate 2023-01-01 [-wait 10s -batch 10]
```

#### CPE
* To download from [Data Feeds](https://nvd.nist.gov/products/cpe) and upsert to database
  * `-data`: data path to import, support local or web path which starts with `http`. If it's not local path, `nvdetl` download and untar the file, the temp file is in `/tmp/`.

```bash
./bin/nvdetl -type cpe -db-user <user> -db-pwd <pwd> -db-endpoint <dbendpoint> -data https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz
```

* To get data from [API](https://nvd.nist.gov/developers/products) and upsert to database
  * `-sdate`: converted to value of `lastModStartDate` key in query string
  * `-edate`: converted to value of `lastModEndDate` key in query string
  * `-wait`(default: `5s`): which is the seconds to sleep between each request to NVD to avoid rate limit
  * `-apikey`: API key for NVD, it's optional
  * `-batch`(default: `1`): batch size to upsert data to database
  * `-timeout`(default: `1m`): timeout for each API request to NVD

```bash
./bin/nvdetl -type cpe -db-user <user> -db-pwd <pwd> -db-endpoint <dbendpoint> -sdate 2022-12-01 -edate 2023-01-01 [-wait 10s -batch 10]
```

## Database
1. Mongo
* Database: `nvd`
  * Collection: `cve`
    * Index: `cveId` (unique). E.g., `CVE-2002-0392`
    * Index: `cpeName`. E.g., `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
    * Index: `cpeNameProductPrefix`. E.g., `cpe:2.3:a:apache:http_server`
    * Index(text): `keyword`, generated from `descriptions.value`
  * Collection: `cpe`
    * Index: `cpeName`. E.g., `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
    * Index(text): `keyword`, generated from `titles.title` and `refs.ref`

The scripts to generate indexs: [mongo-init.js](../service/test/mongo/mongo-init.js), [`initdb`](../db/cmd/initdb/main.go) with `-db-type=mongo` also creates collections and indexs.

### Data
* The records of collection `cve` is the `cve` field of the item from field `vulnerabilities` in [NVD's API](https://nvd.nist.gov/developers/vulnerabilities) response and [DataFeed](https://nvd.nist.gov/vuln/data-feeds).
* The records of collection `cpe` is the `cpe` field of the item from field `products` in [NVD's API](https://nvd.nist.gov/developers/products) response and [DataFeed](https://nvd.nist.gov/products/cpe).

### Upsertion

#### CVE
Since `cveId` is set to unique index, every records that get from the source checks if there's record with same `cveId` in collections.
* If there's no same `cveId` exists, then insert.
* If there's record with same `cveId`, check `lastModified`
  * If incoming record contains latest or equal `lastModified`, then replace.
  * If existed record contains latest `lastModified`, then skip with logging.

Note: The `mitre` time format for `lastModified` is `2023-01-01T00:20:20`, while the `nvd` time format is `2023-01-01T00:20:20.168`. When converting the data from `mitre` to `nvd`, we can only filled the value from `mitre` with `.000`, so `lastModified` that writes to db is different, while they actually represent the same record.
* `mitre`: `2023-01-01T00:20:20.000`
* `nvd`: `2023-01-01T00:20:20.168`

We take data from `nvd` in first priority. Since `lastModified` in `nvd` always `>=` `lastModified` in `mitre` when it represents same CVE modified event, the above upsert logics (**always use latest `lastModified`**) can be automatically applied without differentiating the sources.

The only exception is, there might be very little chance that both contains same `lastModified` (when `nvd` timestamp ends with `.000`... ), and if data from `mitre` is dumped after `nvd`, `mitre` will replace the existing `nvd` record. However, dumping data from `mitre` is expected to be only run for the first time to fill stale CVEs that is not provided by `nvd`. All the data should coming from `nvd` afterwards.

### ETL from the start

To dump all the CVEs to database
1. [One time] Dump from `mitre` (2002 - 2008 or later)
2. [One time] Dump from `nvd` (2008 - <current year>)
3. [Schedule] Keep dumpping from `nvd` to catch up with the latest information

#### Scripts

Below sample is the script to download all CVE from `1999-2022`(step `1.` and `2.`).
* Modify the ending year if needed (currently `2022`)
* Fill the value of `-db-endpoint`, `-db-user`, `-db-pwd`
* Increase `-db-timeout` if getting `upsert cve err: context deadline exceeded`.
  * Note: It takes some resource to import Mitre data feeds for `2021`
* `interval` is the month range to query NVD API. Since the maximum allowable range is 120 consecutive days from NVD API Document, `interval` should be less than `4`
  * `4 months` might get `404` response from NVD since it may exceed `120 days`, we recommand to set this value to `3` or less.
* `-wait` is the time duration between each NVD API request, since NVD has strict rate limit (they recommand to query one time each `6s`)
* `sleep 10` is also used to avoid the rate limit from NVD
* `-batch` is the batch size when upserting data to database

CVE ETL script
* change path of `nvdetl` executable if needed

```bash
set -e

# 1. Import from mitre data feed, which should run before dumping from NVD Vulnerbility CVE API
# source: https://nvd.nist.gov/vuln/data-feeds
for i in {2002..2022};
do
    url=https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$i.json.gz
    ./nvdetl -type cve -db-endpoint <db endpoint> -db-user <db user> -db-pwd <db password> -data $url -db-timeout 5m -batch 100
done

# 2. Import from NVD Vulnerbility CVE API
# source: https://nvd.nist.gov/developers/vulnerabilities

# interval is the range of months query from NVD each time, modify if needed
# E.g., interval=3, query NVD with 3 months each time.
# 1. sdate: 2008-01-01 -> edate: 2008-04-01
# 2. sdate: 2008-04-01 -> edate: 2008-07-01
# 3. ...
interval=3

# count from interval to know the execution count of the scripts each year
# E.g., interval=3, then it needs to run nvdetl 12 / 3 = 4 times to dump data in one year
times=$((12 / interval))

for i in {2008..2022};
do
    for ((j=0;j<$times;j++)); do
        m=$(printf %02d $(($j*$interval+1)))

        sdate=$i-$m-01
        edate=$(date -d "$sdate+$interval month" +%Y-%m-%d)

        ./nvdetl -type cve -db-endpoint <db endpoint> -db-user <db user> -db-pwd <db password> -sdate $sdate -edate $edate -wait 10s -batch 100

        sleep 10
    done
done
```

CPE ETL script
* change path of `nvdetl` executable if needed

```bash
set -e

# 1. Import from mitre data feed, which should run before dumping from NVD CPE Dictionary
# source: https://nvd.nist.gov/products/cpe
url=https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz
./nvdetl -type cpe -db-endpoint <db endpoint> -db-user <db user> -db-pwd <db password> -data $url -db-timeout 5m -batch 100

# 2. Import from NVD Vulnerbility CPE API
# source: https://nvd.nist.gov/developers/products

# interval is the range of months query from NVD each time, modify if needed
# E.g., interval=3, query NVD with 3 months each time.
# 1. sdate: 2008-01-01 -> edate: 2008-04-01
# 2. sdate: 2008-04-01 -> edate: 2008-07-01
# 3. ...
interval=3

# count from interval to know the execution count of the scripts each year
# E.g., interval=3, then it needs to run nvdetl 12 / 3 = 4 times to dump data in one year
times=$((12 / interval))

for i in {2008..2022};
do
    for ((j=0;j<$times;j++)); do
        m=$(printf %02d $(($j*$interval+1)))

        sdate=$i-$m-01
        edate=$(date -d "$sdate+$interval month" +%Y-%m-%d)

        ./nvdetl -type cpe -db-endpoint <db endpoint> -db-user <db user> -db-pwd <db password> -sdate $sdate -edate $edate -wait 10s -batch 100

        sleep 10
    done
done
```
