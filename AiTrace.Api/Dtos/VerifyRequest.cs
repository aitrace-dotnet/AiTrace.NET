using AiTrace.Pro.Verification;

namespace AiTrace.Api.Dtos;

public sealed class VerifyRequest
{
    public VerifyPolicyDto? Policy { get; set; }
    public VerifyScopeDto? Scope { get; set; }
    public bool ExportReports { get; set; } = true;
}

public sealed class VerifyPolicyDto
{
    public bool RequireSignatures { get; set; } = true;
    public bool RequireChainIntegrity { get; set; } = true;
    public bool FailOnMissingFiles { get; set; } = true;
    public bool AllowStartMidChain { get; set; } = true;

    public VerificationPolicy ToVerificationPolicy()
        => new VerificationPolicy
        {
            RequireSignatures = RequireSignatures,
            RequireChainIntegrity = RequireChainIntegrity,
            FailOnMissingFiles = FailOnMissingFiles,
            AllowStartMidChain = AllowStartMidChain
        };
}

public sealed class VerifyScopeDto
{
    public DateTimeOffset? FromUtc { get; set; }
    public DateTimeOffset? ToUtc { get; set; }

    public VerificationScope ToScope()
    {
        if (FromUtc.HasValue && ToUtc.HasValue)
            return VerificationScope.Between(FromUtc.Value, ToUtc.Value);

        return VerificationScope.All();
    }
}
