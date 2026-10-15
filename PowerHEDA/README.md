# Unauthenticated SQL Injection in PowerHEDA v2.5.5.5 (`GetFilterUniqueItems`)

> **Discovered by:** Imraan Khan (Lich-Sec)  
> **Vendor:** IDSC Consulting Pty (Ltd)  
> **Vendor Homepage:** [https://www.heda.co.za/](https://www.heda.co.za/)  
> **Product:** PowerHEDA (Higher Education Data Analyser)  
> **Version:** 2.5.5.5 (build path `PowerHEDA V255`)  
> **Date Discovered:** 2026-09-02  
> **CVE Status:** Submitted to MITRE — Pending Assignment  
> **CWE:** CWE-89  
> **Severity:** Critical (CVSS v3.1: 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)  
> **Tested On:** IIS / ASP.NET / Microsoft SQL Server

This folder is the **stable public reference** for MITRE. Do not rename it after the CVE ID is assigned; update the CVE Status line instead.

---

## Disclaimer

This issue was found during an authorised security assessment. The customer hostname is withheld. The proof below is **identity-only SQL**. It does not include operating-system command execution or extraction of student, staff, or academic records.

---

## Summary

PowerHEDA v2.5.5.5 exposes a query-builder web service at `HedaDataRetrieval.asmx`. The `GetFilterUniqueItems` method takes a JSON body and interpolates the attacker-controlled `fColumn` value into a T-SQL **identifier** (column name).

A non-column value returns `Invalid column name '1'`. Closing the identifier with `]` and injecting a derived table executes attacker SQL as the application database principal.

**No application cookie, token, or registered user is required.** The same JSON POST succeeds with and without Forms Authentication.

Exception stacks on the tested build name IDSC product source, not a campus-only customisation:

```text
at heda_be.Data.db.GetData(...) in ...\heda_be\Data\db.vb:line 201
at PowerHEDA.QueryBuilderDataRetrieval.GetFilterUniqueItems(...)
   in ...\PowerHEDA V255\PowerHEDA\webservices\HedaDataRetrieval.asmx.vb:line 600
```

---

## Affected configuration

| Item | Value |
|------|--------|
| HTTP | `POST` JSON, `Content-Type: application/json` |
| Path (typical) | `/PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems` |
| Body fields | `fColumn` (sink), `fKey`, `fWhere` |
| Auth | None observed on this method |
| Confirmed version | **2.5.5.5** (footer `PowerHEDA © 2019`; exception path `PowerHEDA V255`) |

`fKey` and `fWhere` are accepted by the method. **`fColumn` is the confirmed injection sink.** Sibling methods `GetQuickCriteriaValues` and `BuildFormulaBuilder` / `fSQL` were not raw SQL on this build and are not claimed here.

Proof-of-concept requests are in [`POC/`](POC/).

---

## Root cause

`GetFilterUniqueItems` concatenates `fColumn` into a statement of the form:

```sql
SELECT DISTINCT [fColumn] FROM ...
```

T-SQL identifiers cannot be parameterised the same way as literals. The fix is an **allow-list** of column names, or a quoted identifier built only from validated `[A-Za-z0-9_]` characters.

---

## Impact

A remote attacker who can reach the ASMX endpoint can run arbitrary SQL as the PowerHEDA database principal **without logging in**. That typically means read and alter of the application database. Additional impact (for example operating-system commands) depends on the customer SQL login’s rights and is a deployment issue, not a second product defect.

---

## Recommendation

1. Parameterise or allow-list `fColumn`. Do not concatenate client input into SQL identifiers.
2. Require authentication on `HedaDataRetrieval.asmx` query-builder methods.
3. Apply the vendor patch when IDSC publishes a fixed PowerHEDA build.
4. Until a patch is available, restrict the ASMX endpoint to an approved network.

---

## Disclosure timeline

| Date | Event |
|------|--------|
| 2026-09-02 | Vulnerability confirmed |
| 2026-10-15 | Vendor (IDSC) notified |
| Pending | CVE assignment / public record |

---

## References

- This writeup (MITRE-stable): https://github.com/stSLAYER/ZeroDayVulnerabilities-/tree/main/PowerHEDA
- Vendor product: https://www.heda.co.za/
