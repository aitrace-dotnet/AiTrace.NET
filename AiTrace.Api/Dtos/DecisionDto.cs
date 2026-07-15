namespace AiTrace.Api.Dtos;

/// <summary>
/// Request body for POST /api/decisions.
/// Both Prompt and Output are required; validation returns HTTP 400 if missing.
/// </summary>
public sealed class DecisionDto
{
    public string Prompt { get; set; } = string.Empty;
    public string Output { get; set; } = string.Empty;
    public string? Model { get; set; }
    public string? UserId { get; set; }
    public Dictionary<string, object?>? Metadata { get; set; }
}
