using CadesDss.Crypto;

namespace CadesDss.Signature;

public class SignaturePolicyInfo
{
    public SignaturePolicyInfo()
    {
    }

    public string? PolicyIdentifier { get; set; }

    public string? PolicyHash { get; set; }

    public DigestMethod PolicyDigestAlgorithm { get; set; } = DigestMethod.SHA1;
}
