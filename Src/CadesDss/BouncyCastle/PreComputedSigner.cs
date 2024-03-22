using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace CadesDss.BouncyCastle;

internal class PreComputedSigner : ISigner
{
    private byte[] PreComputedSignature { get; set; }
    private IDigest digest;

    // Signer CUSTOM CODE
    private byte[]? currentSignature;

    /// <summary>The default constructor for PreComputedSigner.</summary>
    /// <remarks>The default constructor for PreComputedSigner.</remarks>
    /// <param name="algorithmName"></param>
    public PreComputedSigner()
        : this(new byte[0])
    {
    }

    /// <param name="preComputedSignature">the preComputedSignature to set</param>
    public PreComputedSigner(byte[] preComputedSignature)
    {
        PreComputedSignature = preComputedSignature;
        digest = new NullDigest();
    }

    public string AlgorithmName
    {
        get { return "NONE"; }
    }

    public void Init(bool forSigning, ICipherParameters parameters)
    {
        Reset();
    }

    public void Update(byte input)
    {
        digest.Update(input);
    }

    public void BlockUpdate(byte[] input, int inOff, int length)
    {
        digest.BlockUpdate(input, inOff, length);
    }

    public byte[] GenerateSignature()
    {
        if (PreComputedSignature.Length > 0)
        {
            currentSignature = PreComputedSignature;
            return PreComputedSignature;
        }
        else
        {
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            // Signer CUSTOM CODE
            currentSignature = hash;
            return currentSignature;
        }
    }

    // Signer CUSTOM CODE
    public byte[]? CurrentSignature()
    {
        return currentSignature;
    }

    public bool VerifySignature(byte[] signature)
    {
        throw new NotImplementedException();
    }

    public void Reset()
    {
        // Signer CUSTOM CODE
        currentSignature = null;
        digest.Reset();
    }

    public int GetMaxSignatureSize()
    {
        throw new NotImplementedException();
    }
}
