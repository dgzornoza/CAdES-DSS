using CadesDss.Crypto;
using CadesDss.Helpers;
using CadesDss.Signature;
using CadesDss.Upgraders.Parameters;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using BcCms = Org.BouncyCastle.Asn1.Cms;

namespace CadesDss.Upgraders;

public class CadesTUpgrader : ICadesUpgrader
{
    public void Upgrade(SignatureDocument signatureDocument, SignerInfoNode signerInfoNode, UpgradeParameters parameters)
    {
        BcCms.AttributeTable unsigned = signerInfoNode.SignerInformation.UnsignedAttributes;

        var unsignedAttrHash = unsigned == null ? 
            new Dictionary<DerObjectIdentifier, BcCms.Attribute>() :
            signerInfoNode.SignerInformation.UnsignedAttributes.ToDictionary();

        BcCms.Attribute signatureTimeStamp = GetTimeStampAttribute(PkcsObjectIdentifiers.IdAASignatureTimeStampToken
            , parameters.TsaClient, parameters.DigestMethod, signerInfoNode.SignerInformation.GetSignature());

        unsignedAttrHash.Add(PkcsObjectIdentifiers.IdAASignatureTimeStampToken, signatureTimeStamp);

        SignerInformation newsi = SignerInformation.ReplaceUnsignedAttributes(signerInfoNode.SignerInformation,
            new BcCms.AttributeTable(unsignedAttrHash));

        signerInfoNode.SignerInformation = newsi;
    }

    private BcCms.Attribute GetTimeStampAttribute(DerObjectIdentifier oid, TimeStampHelpers tsa, 
        DigestMethod digestMethod, byte[] messageImprint)
    {
        byte[] toTimeStamp = digestMethod.CalculateDigest(messageImprint);
        byte[] timeStampToken = tsa.GetTimeStamp(toTimeStamp, digestMethod, true);

        BcCms.Attribute signatureTimeStamp = new BcCms.Attribute(oid, new DerSet(Asn1Object.FromByteArray(timeStampToken)));

        return signatureTimeStamp;
    }
}
