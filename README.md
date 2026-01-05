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
