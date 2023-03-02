conn = new Mongo();

db = conn.getDB("nvd");

db.cve.createIndex({ "cveId": 1 }, { unique: true, name: "cveId" });
db.cve.createIndex({ "configurations.nodes.cpeMatch.criteria": 1 }, { name: "cpeName" });
db.cve.createIndex({ "configurations.nodes.cpeMatch.criteriaProductPrefix": 1 }, { name: "cpeNameProductPrefix" });
db.cve.createIndex({ "descriptions.value": "text" }, { name: "keyword" });

db.cpe.createIndex({ "cpeName": 1 }, { unique: true, name: "cpeName" });
db.cpe.createIndex({ "titles.title": "text", "refs.ref": "text" }, { name: "keyword" });
