namespace AiTrace.Pro.Verification;

public static class ComplianceSummaryBuilder
{
    public static ComplianceVerificationSummary FromResult(
        VerificationResult result,
        int filesVerified,
        DateTimeOffset? firstUtc,
        DateTimeOffset? lastUtc,
        bool anySignaturePresent,
        bool signatureRequired)
    {
        var signatureStatus = SignatureStatus.NotChecked;

        if (signatureRequired)
        {
            // If policy requires signatures, result must have checked them.
            signatureStatus = result.IsValid ? SignatureStatus.Valid : SignatureStatus.Invalid;
            if (!anySignaturePresent)
                signatureStatus = SignatureStatus.Missing;
        }
        else
        {
            // If not required, we only label Valid/Invalid if we actually checked at least one.
            if (result.SignatureChecked)
                signatureStatus = result.SignatureValid ? SignatureStatus.Valid : SignatureStatus.Invalid;
        }

        var integrityOk = result.Status != VerificationStatus.HashMismatch && result.Status != VerificationStatus.ParseError;
        var chainOk = result.Status != VerificationStatus.ChainBroken;

        return new ComplianceVerificationSummary
        {
            Status = result.Status,
            IsValid = result.IsValid,

            IntegrityVerified = result.IsValid || integrityOk,
            ChainVerified = result.IsValid || chainOk,

            AnySignaturePresent = anySignaturePresent,
            SignatureRequired = signatureRequired,
            SignatureStatus = signatureStatus,

            FilesVerified = filesVerified,
            RecordsVerified = filesVerified,

            FirstTimestampUtc = firstUtc,
            LastTimestampUtc = lastUtc,

            FailedIndex = result.FailedIndex,
            FailedFileName = result.FileName,
            Reason = result.Reason
        };
    }
}