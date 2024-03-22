using Org.BouncyCastle.Crypto;

namespace CadesDss.Crypto;

internal class NullPrivateKey : AsymmetricKeyParameter
{
    public NullPrivateKey(): base(true) { }

    public override string ToString() => "NULL";
}
