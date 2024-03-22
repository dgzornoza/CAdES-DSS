using CadesDss.Crypto;
using System.Security.Cryptography.X509Certificates;

namespace CadesDss.Signature;

public enum SignaturePackaging
{
    DETACHED_EXPLICIT,
    ATTACHED_IMPLICIT
}

public record SignatureParameters()
{
    public Signer? Signer { get; set; }
    public X509Certificate? Certificate { get; set; }
    public DigestMethod DigestMethod { get; set; } = DigestMethod.SHA1;
    public byte[]? PreCalculatedDigest { get; set; }
    public DateTime SigningDate { get; set; } = DateTime.Now;
    public string? SignerRole { get; set; }
    public List<SignatureCommitment> SignatureCommitments { get; private set; } = new();
    public SignatureProductionPlace? SignatureProductionPlace { get; set; }
    public SignaturePolicyInfo? SignaturePolicyInfo { get; set; }
    public SignaturePackaging SignaturePackaging { get; set; }
    public string? MimeType { get; set; }
}
