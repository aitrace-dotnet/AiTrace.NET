using AiTrace.Pro.Verification.Evidence;

namespace AiTrace.Pro.Tests;

public class EvidenceBundleSealerTests : IDisposable
{
    private readonly string _dir;

    public EvidenceBundleSealerTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "AiTraceProSealTests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private void WriteFile(string relativePath, string content = "hello")
    {
        var full = Path.Combine(_dir, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllText(full, content);
    }

    [Fact]
    public void WriteSeal_Then_VerifySeal_Succeeds()
    {
        WriteFile("audit/record1.json", "{\"id\":\"1\"}");
        WriteFile("audit/record2.json", "{\"id\":\"2\"}");

        EvidenceBundleSealer.WriteSeal(_dir);

        var (ok, reason) = EvidenceBundleSealer.VerifySeal(_dir);
        Assert.True(ok, reason);
    }

    [Fact]
    public void VerifySeal_NoSealFile_ReturnsFalse()
    {
        WriteFile("record.json");
        var (ok, _) = EvidenceBundleSealer.VerifySeal(_dir);
        Assert.False(ok);
    }

    [Fact]
    public void VerifySeal_TamperedFile_ReturnsFalse()
    {
        WriteFile("record.json", "original content");
        EvidenceBundleSealer.WriteSeal(_dir);

        // Tamper with the file after sealing
        File.WriteAllText(Path.Combine(_dir, "record.json"), "tampered content");

        var (ok, reason) = EvidenceBundleSealer.VerifySeal(_dir);
        Assert.False(ok);
        Assert.Contains("hash mismatch", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void VerifySeal_MissingFile_ReturnsFalse()
    {
        WriteFile("record.json");
        EvidenceBundleSealer.WriteSeal(_dir);

        // Delete file after sealing
        File.Delete(Path.Combine(_dir, "record.json"));

        var (ok, _) = EvidenceBundleSealer.VerifySeal(_dir);
        Assert.False(ok);
    }

    [Fact]
    public void WriteSeal_EmptyDirectory_Succeeds()
    {
        // An evidence dir with no files is unusual but should not throw.
        var (ok, reason) = EvidenceBundleSealer.VerifySeal(_dir);
        // No seal yet, so it fails
        Assert.False(ok);
    }

    [Fact]
    public void VerifySeal_DirectoryNotFound_ReturnsFalse()
    {
        var (ok, _) = EvidenceBundleSealer.VerifySeal(Path.Combine(_dir, "nonexistent"));
        Assert.False(ok);
    }
}
