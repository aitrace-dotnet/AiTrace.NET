namespace AiTrace.Pro.Verification;

public enum VerificationStatus
{
    Ok = 0,

    // Integrity / chain issues
    HashMismatch,
    ChainBroken,

    // Signature issues
    SignatureInvalid,
    SignatureMissing,
    SignatureServiceMissing,

    // Input / file issues
    DirectoryNotFound,
    NoFiles,
    ParseError
}
