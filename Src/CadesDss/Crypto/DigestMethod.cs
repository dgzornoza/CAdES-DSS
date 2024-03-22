using System.Security.Cryptography;

namespace CadesDss.Crypto;

public enum DigestMethodAlgorithm
{
    SHA1,
    SHA256,
    SHA512
}

public class DigestMethod
{
    private readonly DigestMethodAlgorithm name;
    private readonly string uri;
    private readonly string oid;

    private DigestMethod(DigestMethodAlgorithm name, string uri, string oid)
    {
        this.name = name;
        this.uri = uri;
        this.oid = oid;
    }

    public static DigestMethod SHA1 => new(DigestMethodAlgorithm.SHA1, "http://www.w3.org/2000/09/xmldsig#sha1", "1.3.14.3.2.26");
    public static DigestMethod SHA256 => new(DigestMethodAlgorithm.SHA256, "http://www.w3.org/2001/04/xmlenc#sha256", "2.16.840.1.101.3.4.2.1");
    public static DigestMethod SHA512 => new(DigestMethodAlgorithm.SHA512, "http://www.w3.org/2001/04/xmlenc#sha512", "2.16.840.1.101.3.4.2.3");

    public DigestMethodAlgorithm Name => name;
    public string Uri => uri;
    public string Oid => oid;


    public static DigestMethod GetByOid(string oid)
    {
        if (oid == SHA1.Oid)
        {
            return SHA1;
        }
        else if (oid == SHA256.Oid)
        {
            return SHA256;
        }
        else if (oid == SHA512.Oid)
        {
            return SHA512;
        }
        else
        {
            throw new Exception("Unsupported digest method");
        }
    }

    public static DigestMethod GetByName(DigestMethodAlgorithm algoName) => algoName switch
    {
        DigestMethodAlgorithm.SHA1 => SHA1,
        DigestMethodAlgorithm.SHA256 => SHA256,
        DigestMethodAlgorithm.SHA512 => SHA512,
        _ => throw new KeyNotFoundException("unsupported algorithm: " + algoName)
    };

    public HashAlgorithmName GetHashAlgorithmName() => name switch
    {
        DigestMethodAlgorithm.SHA1 => HashAlgorithmName.SHA1,
        DigestMethodAlgorithm.SHA256 => HashAlgorithmName.SHA256,
        DigestMethodAlgorithm.SHA512 => HashAlgorithmName.SHA512,
        _ => throw new KeyNotFoundException("unsupported algorithm:")
    };

    public byte[] CalculateDigest(byte[] data)
    {
        using var hashAlgorithm = GetHashAlgorithm();
        return hashAlgorithm.ComputeHash(data);
    }

    private HashAlgorithm GetHashAlgorithm() => name switch
    {
        DigestMethodAlgorithm.SHA1 => System.Security.Cryptography.SHA1.Create(),
        DigestMethodAlgorithm.SHA256 => System.Security.Cryptography.SHA256.Create(),
        DigestMethodAlgorithm.SHA512 => System.Security.Cryptography.SHA512.Create(),
        _ => throw new KeyNotFoundException("Unsupported algorithm")
    };
}
