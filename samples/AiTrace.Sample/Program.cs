using AiTrace;

AiTrace.AiTrace.Configure(o =>
{
    o.StoreContent = true;
    o.BasicRedaction = true;
    // o.Store = new JsonAuditStore(@"C:\temp\aitrace"); // optional
});

var decision = new AiDecision
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
};

await AiTrace.AiTrace.LogDecisionAsync(decision);

Console.WriteLine("Logged. Check the ./aitrace folder next to the executable.");
Console.WriteLine($"Base directory: {AppContext.BaseDirectory}");
