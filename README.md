> ⚠️ **Status: Experimental**
>  
> AiTrace.NET is under active development.  
> APIs may change. Not production-ready yet.

# AiTrace.NET
**Audit & Proof Layer for AI Decisions in .NET**

[![NuGet](https://img.shields.io/nuget/vpre/AiTrace.svg)](https://www.nuget.org/packages/AiTrace/)

> *Know exactly what your AI did, when, and why.*

---

## Install

~~~bash
dotnet add package AiTrace --prerelease
~~~

---

## Quickstart

By default, audit files are written to a local `./aitrace` folder next to your application's executable.

~~~csharp
using AiTrace;

AiTrace.AiTrace.Configure(o =>
{
    o.StoreContent = true;
    o.BasicRedaction = true;
});

await AiTrace.AiTrace.LogDecisionAsync(new AiDecision
{
    Prompt = "Summarize: The quick brown fox jumps over the lazy dog.",
    Output = "A fox jumps over a dog.",
    Model = "demo-model",
    UserId = "user-123",
    Metadata = new Dictionary<string, object?>
    {
        ["Feature"] = "Demo",
        ["CorrelationId"] = Guid.NewGuid().ToString("n")
    }
});

Console.WriteLine("Audit file created in ./aitrace next to your app.");
~~~

This creates an **immutable JSON audit record** containing:
- timestamp (UTC)
- cryptographic hash
- model identifier
- user identifier
- prompt and output (optional)
- structured metadata

---

## API (Local)

A minimal API is included in the solution (`AiTrace.Api`) for testing audit logging and verification via HTTP.

### Configure

Set your keys and audit folder in `AiTrace.Api/appsettings.json`:

~~~json
{
  "AiTraceApi": {
    "AuditRoot": "aitrace",
    "PrivateKeyPath": "C:\\temp\\aitrace_private.pem",
    "PublicKeyPath": "C:\\temp\\aitrace_public.pem"
  }
}
~~~

### Run

~~~bash
cd AiTrace.Api
dotnet run
~~~

Then open Swagger:

- `https://localhost:7266/swagger`
- or `http://localhost:5095/swagger` (depends on your launchSettings)

### Endpoints

- `POST /api/decisions` — log an audit record
- `POST /api/verify` — verify integrity/signatures and optionally export reports
- `GET /api/reports/text` — get latest text report
- `GET /api/reports/json` — get latest JSON report

Example request body for `POST /api/decisions`:

~~~json
{
  "prompt": "Explain what an audit trail is.",
  "output": "An audit trail is a tamper-evident record of actions.",
  "model": "demo-model",
  "userId": "user-123",
  "metadata": {
    "source": "swagger"
  }
}
~~~

Example request body for `POST /api/verify`:

~~~json
{
  "exportReports": true,
  "policy": {
    "requireSignatures": true,
    "requireChainIntegrity": true,
    "failOnMissingFiles": true,
    "allowStartMidChain": true
  },
  "scope": {
    "fromUtc": "2026-01-07T00:00:00Z",
    "toUtc": "2026-01-14T23:59:59Z"
  }
}
~~~

Reports are written under:

- `./aitrace/reports/compliance_report.txt`
- `./aitrace/reports/compliance_report.json`

---

## Verification & Integrity

AiTrace audit records are designed to be **verifiable after the fact**.

Each record includes:
- a cryptographic hash
- an optional hash chain (`PrevHashSha256`)
- optional cryptographic signatures (Pro)

Audit trails can be verified programmatically to detect:
- record tampering
- missing or altered files
- broken chains
- invalid signatures

Verification produces:
- a structured machine-readable result
- a human-readable compliance report summarizing integrity and authenticity
- supports strict verification policies, time-scoped audits, and compliance-ready reports (TXT / JSON)

---

## VerificationStatus (Pro)

When verifying an audit trail, AiTrace returns a structured status indicating the outcome.

Typical statuses include:
- `Ok`
- `HashMismatch`
- `ChainBroken`
- `SignatureInvalid`
- `SignatureServiceMissing`
- `SignatureRequiredButMissing`
- `NoFiles`
- `ParseError`

This allows verification results to be:
- deterministic
- audit-friendly
- suitable for automation, reporting, or compliance workflows

---

## Cryptographic Signatures (Pro)

AiTrace Pro supports **cryptographic signing** of audit records.

When enabled:
- the final audit record hash is signed (RSA-SHA256)
- signatures provide **non-repudiation**
- records can be independently verified using a public key

This enables organizations to prove that:
- a record was produced by a trusted system
- the record has not been altered
- the audit trail is legally defensible

Signatures are applied **after all record data is finalized**, ensuring stability.

---

## Compliance Reports (Pro)

AiTrace Pro can generate **compliance-ready audit reports** from an audit directory.

Supported formats:
- plain text (`compliance_report.txt`)
- JSON (`compliance_report.json`)

Reports summarize:
- overall verification status
- record and chain integrity
- signature requirements and validity
- number of files and records verified
- time range covered by the audit trail
- detection of post-decision tampering

These reports are designed to be:
- attached to regulatory filings
- shared with legal or compliance teams
- archived as formal audit evidence

---

## AiTrace for Compliance & Legal Teams

AiTrace provides a **cryptographic proof layer** for automated decisions.

It enables organizations to prove, **after the fact**, that:
- a specific automated decision occurred at a specific time
- the exact inputs and outputs involved are known
- the record has not been altered since it was created

AiTrace is designed for **post-incident analysis**, audits, and regulatory inquiries.  
It does **not** explain or justify decisions — it proves **what happened**.

Typical use cases include:
- contested automated decisions
- regulatory or compliance audits
- internal investigations
- legal or risk documentation

**AiTrace transforms automated decisions into technically and legally defensible evidence.**

---

## Typical use cases

AiTrace.NET is useful when you need to:
- keep an auditable record of AI-driven decisions
- investigate incidents or user disputes involving AI output
- comply with internal or external audit requirements
- demonstrate integrity of automated systems

---

## Example scenarios

AiTrace.NET can be used, for example, to audit:
- loan approval or risk scoring decisions
- automated content moderation systems
- AI-generated recommendations shown to users
- internal tools where AI output impacts business decisions

---

## Why AiTrace.NET exists

AI is increasingly used to:
- make automated decisions
- generate recommendations
- filter, score, or classify data

But most applications **cannot prove**:
- which prompt was used
- which model generated the output
- what data was provided
- when the decision happened
- whether the output was later altered

When something goes wrong, teams are left with:
- incomplete logs
- no versioning
- no integrity guarantees

**AiTrace.NET creates a verifiable audit trail for AI decisions.**

---

## What AiTrace.NET does

AiTrace.NET is a lightweight .NET library that:

- records AI prompts and outputs
- hashes and timestamps each decision
- guarantees integrity of stored data
- enables future audits and compliance checks
- works locally with no required infrastructure

No dashboards.  
No cloud dependency.  
No sales calls.  

Just facts.

---

## Storage & privacy

By default, AiTrace.NET:
- stores data locally (JSON files)
- never sends data externally
- keeps full control inside your application

Cloud or centralized storage can be added later.

---

## Who is this for?

- .NET developers using AI in production
- Enterprise teams with compliance requirements
- Regulated industries (finance, HR, healthcare)
- Anyone who needs provable AI behavior

---

## What this is NOT

- Not a chatbot
- Not an AI wrapper
- Not an analytics dashboard
- Not a monitoring SaaS

AiTrace.NET focuses on **truth**, not opinions.

---

## Roadmap

- Prompt versioning
- Output diffing
- Centralized audit store (optional)
- Compliance-ready exports (PDF / JSON)
- Enterprise features (SLA, support, encryption policies)

---

## Philosophy

AI explanations can change.  
Facts cannot.

AiTrace.NET records what actually happened —  
so you can prove it later.

---

## License

MIT License
