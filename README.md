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
- or `http://localhost:5095/swagger`

### Endpoints

- `POST /api/decisions` — log an audit record  
- `POST /api/verify` — verify integrity/signatures and optionally export reports  
- `GET /api/reports/text` — get latest text report  
- `GET /api/reports/json` — get latest JSON report  

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

---

## 🔍 Audit Diffing & Evidence Comparison (Pro)

AiTrace Pro includes **audit-only diffing** capabilities designed for
**forensic verification**, **regulatory review**, and **CI compliance gates**.

### Diff audit trails between two evidence bundles

The `diff-audit` command compares **only `audit/*.json` records**
between two sealed evidence bundles.

~~~bash
dotnet run -- diff-audit "<bundleA>" "<bundleB>"
~~~

It detects:
- **added** audit records
- **removed** audit records
- **modified** audit records

Other files (reports, metadata, manifests) are ignored.

---

### Semantic audit classification

Each comparison is classified as:

- **IDENTICAL** — audit trails are byte-for-byte equivalent
- **EXTENDED** — new audit records were appended (append-only)
- **ALTERED** — records were removed or modified

This distinction is critical for legal and compliance scenarios.

---

### Append-only & integrity assertions

Assertions allow enforcement in CI pipelines or compliance checks:

~~~bash
# Fail unless audit trails are identical
dotnet run -- diff-audit --assert-identical "<bundleA>" "<bundleB>"

# Fail unless audit trail is append-only
dotnet run -- diff-audit --assert-append-only "<bundleA>" "<bundleB>"
~~~

Exit codes are deterministic and machine-actionable.

---

### Deterministic audit hash

Each audit trail produces a **stable SHA-256 audit hash**, computed from
ordered `(path, sha256)` pairs of `audit/*.json`.

This allows fingerprinting the audit history independently of:
- reports
- bundle metadata
- export timestamps

---

### JSON output & file export

For automation and archiving:

~~~bash
dotnet run -- diff-audit --json --out diff_audit.json "<bundleA>" "<bundleB>"
~~~

The JSON output includes:
- bundle paths
- bundle hashes
- audit hashes
- added / removed / modified records
- semantic status
- exit code
- assertion results (if any)

This makes audit evolution **scriptable**, **auditable**, and suitable for **regulatory review**.
---

### CI / Automation Example

The `diff-audit` command is designed to be CI-friendly and can be used
as a compliance gate in automated pipelines.

#### Example: fail CI if audit trail was altered

~~~bash
dotnet run -- diff-audit --assert-append-only --quiet "<previous_bundle>" "<current_bundle>"

if [ $? -ne 0 ]; then
  echo "Audit trail integrity violation detected"
  exit 1
fi
~~~

## Cryptographic Signatures (Pro)

AiTrace Pro supports **cryptographic signing** of audit records.

When enabled:
- the final audit record hash is signed (RSA-SHA256)
- signatures provide **non-repudiation**
- records can be independently verified using a public key

Signatures are applied **after all record data is finalized**.

---

## Compliance Reports (Pro)

AiTrace Pro can generate **compliance-ready audit reports** from an audit directory.

Supported formats:
- `compliance_report.txt`
- `compliance_report.json`

Reports summarize:
- verification status
- record and chain integrity
- signature requirements and validity
- number of files verified
- time range covered

---

## Evidence Bundles (Pro)

AiTrace Pro can export a **portable, regulator-grade evidence bundle** from an audit directory.

An evidence bundle is a **self-contained, immutable snapshot** of an AI audit trail.

### Evidence Bundle Structure

evidence_YYYYMMDD_HHMMSS/ ├── 
audit/ │   ├── 
20260121_185311116_xxxxx.json │   
└── ... ├── compliance_report.txt 
├── compliance_report.json ├── 
README.txt ├── manifest.txt ├── 
public_key.pem   (optional) └── 
seal.json

---

## Evidence Bundle Sealing (Pro)

AiTrace Pro supports **cryptographic sealing of evidence bundles**.

After an evidence bundle is exported, the entire folder can be sealed using a deterministic SHA-256 process.

### What is `seal.json`?

`seal.json` contains:
- a SHA-256 hash for **every file** in the bundle
- a deterministic **global bundle hash**
- timestamp and algorithm metadata

Any modification to the bundle will be detected.

This allows the bundle to serve as a point-in-time cryptographic evidence snapshot.

### Seal an Evidence Bundle

~~~csharp
using AiTrace.Pro.Verification.Evidence;

var sealPath = EvidenceBundleSealer.WriteSeal(evidenceBundleDirectory);
Console.WriteLine($"Seal written to: {sealPath}");
~~~

### Verify a Sealed Bundle (Independent Check)

~~~csharp
var (ok, reason) = EvidenceBundleSealer.VerifySeal(evidenceBundleDirectory);

Console.WriteLine(ok
    ? "Seal OK: bundle is intact"
    : $"Seal FAIL: {reason}");
~~~

This enables:
- offline verification
- third-party audits
- regulator review
- long-term evidence archiving

---

## AiTrace for Compliance & Legal Teams

AiTrace provides a **cryptographic proof layer** for automated decisions.

It enables organizations to prove, **after the fact**, that:
- a specific decision occurred
- at a specific time
- with specific inputs and outputs
- without later alteration

AiTrace does **not** explain decisions — it proves **what happened**.

---

## Licensing & Usage

AiTrace.NET is released under the **MIT License**.

You may:
- use the source code freely
- modify and fork the project
- use AiTrace.NET for internal or experimental use

### AiTrace.Pro (Compliance & Production Usage)

AiTrace.Pro includes:
- cryptographic signatures
- strict verification policies
- compliance reports
- evidence bundles
- bundle sealing and verification

While source code is visible, **production or compliance-grade usage requires a valid license**.

Forking or reimplementing AiTrace.Pro:
- does **not** grant compliance guarantees
- does **not** provide legal assurance

---

## Philosophy

AI explanations can change.  
Facts cannot.

AiTrace.NET records what actually happened —  
so you can prove it later.

---

## License

MIT License
