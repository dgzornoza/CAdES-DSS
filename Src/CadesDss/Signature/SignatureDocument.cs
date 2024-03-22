using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using System.Collections;

namespace CadesDss.Signature;

public class SignatureDocument
{        
    private readonly List<SignerInfoNode> nodes = new();
    private readonly IList certs;
    private readonly SignaturePackaging signaturePackaging;

    private CmsSignedData signedData;

    public SignatureDocument(CmsSignedData signedData)
    {
        this.signedData = signedData;
        certs = CmsUtilities.GetCertificatesFromStore(this.signedData.GetCertificates("Collection"));
        signaturePackaging = this.signedData.SignedContent != null ? SignaturePackaging.ATTACHED_IMPLICIT : SignaturePackaging.DETACHED_EXPLICIT;
        ReadSignersInfo();
    }

    public CmsSignedData SignedData
    {
        get
        {
            return signedData;
        }

        set
        {
            signedData = value;
        }
    }

    public Stream? Content
    {
        get
        {
            if (signedData.SignedContent != null)
            {
                using MemoryStream ms = new();
                signedData.SignedContent.Write(ms);
                ms.Seek(0, SeekOrigin.Begin);

                return ms;
            }
            else
            {
                return null;
            }
        }
    }

    public SignaturePackaging SignaturePackaging
    {
        get
        {
            return signaturePackaging;
        }
    }

    public IList<SignerInfoNode> SignersInfo
    {
        get
        {
            return nodes;
        }
    }

    public IList Certificates
    {
        get
        {
            return certs;
        }
    }

    public byte[] GetDocumentBytes()
    {
        return signedData.GetEncoded();
    }

    public void Save(Stream output)
    {
        byte[] encoded = signedData.GetEncoded();

        output.Write(encoded, 0, encoded.Length);
    }

    internal void ReBuildCmsSignedData()
    {
        IList<SignerInformation> list = new List<SignerInformation>();

        foreach (var node in nodes)
        {
            list.Add(GetSignerInformation(node));
        }

        signedData = CmsSignedData.ReplaceSigners(signedData, new SignerInformationStore(list.ToArray()));
        ReadSignersInfo();
    }

    private void ReadSignersInfo()
    {
        nodes.Clear();

        foreach (var signer in signedData.GetSignerInfos().GetSigners())
        {
            SignerInfoNode node = new SignerInfoNode((SignerInformation)signer, this);

            nodes.Add(node);
        }
    }

    private SignerInformation GetSignerInformation(SignerInfoNode signerInfoNode)
    {
        if (signerInfoNode.CounterSignatures.Count > 0)
        {
            var nodes = GetCounterSignatures(signerInfoNode);

            AttributeTable attributes = signerInfoNode.SignerInformation.UnsignedAttributes.Remove(CmsAttributes.CounterSignature);

            SignerInformation newSignerInformation = SignerInformation.ReplaceUnsignedAttributes(signerInfoNode.SignerInformation, attributes);

            return SignerInformation.AddCounterSigners(newSignerInformation, new SignerInformationStore(nodes.ToArray()));
        }
        else
        {
            return signerInfoNode.SignerInformation;
        }
    }

    private static List<SignerInformation> GetCounterSignatures(SignerInfoNode node)
    {
        List<SignerInformation> list = new();

        foreach (var counterSignNode in node.CounterSignatures)
        {
            if (counterSignNode.CounterSignatures.Count > 0)
            {
                var nodes = GetCounterSignatures(counterSignNode);

                AttributeTable attributes = counterSignNode.SignerInformation.UnsignedAttributes.Remove(CmsAttributes.CounterSignature);

                SignerInformation newSignerInformation = SignerInformation.ReplaceUnsignedAttributes(counterSignNode.SignerInformation, attributes);

                list.Add(SignerInformation.AddCounterSigners(newSignerInformation, new SignerInformationStore(nodes.ToArray())));
            }
            else
            {
                list.Add(counterSignNode.SignerInformation);
            }
        }

        return list;
    }
}

