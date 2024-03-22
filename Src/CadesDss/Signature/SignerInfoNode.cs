using CadesDss.Crypto;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using BcCms = Org.BouncyCastle.Asn1.Cms;

namespace CadesDss.Signature;

public class SignerInfoNode
{
    private SignatureDocument sigDocument;

    private SignerInformation signerInformation;

    private IList<SignerInfoNode> counterSignatures;

    private DateTime? signingDate;

    private IEnumerable<string> signerRoles;

    private TimeStampToken timeStamp;

    private X509Certificate certificate;


    public SignerInformation SignerInformation
    {
        get
        {
            return signerInformation;
        }

        set
        {
            signerInformation = value;
            ReadInformation();
            sigDocument.ReBuildCmsSignedData();
        }
    }

    public IList<SignerInfoNode> CounterSignatures
    {
        get
        {
            return counterSignatures;
        }
    }

    public DateTime? SigningDate
    {
        get
        {
            return signingDate;
        }
    }

    public IEnumerable<string> SignerRoles
    {
        get
        {
            return signerRoles;
        }
    }

    public TimeStampToken TimeStamp
    {
        get
        {
            return timeStamp;
        }
    }

    public X509Certificate Certificate
    {
        get
        {
            return certificate;
        }
    }

    internal SignerInfoNode(SignerInformation signerInformation, SignatureDocument sigDocument)
    {
        this.signerInformation = signerInformation;
        this.sigDocument = sigDocument;
        ReadInformation();
    }

    private void ReadInformation()
    {
        if (signerInformation.SignedAttributes[PkcsObjectIdentifiers.Pkcs9AtSigningTime] != null)
        {
            signingDate = DerUtcTime.GetInstance(signerInformation.SignedAttributes[PkcsObjectIdentifiers.Pkcs9AtSigningTime].AttrValues[0]).ToDateTime().ToLocalTime();
        }

        if (signerInformation.SignedAttributes[PkcsObjectIdentifiers.IdAAEtsSignerAttr] != null)
        {
            var signerAttr = SignerAttribute.GetInstance(signerInformation.SignedAttributes[PkcsObjectIdentifiers.IdAAEtsSignerAttr].AttrValues[0]);

            List<string> claimedRoles = new List<string>();

            foreach (BcCms.Attribute claimedAttr in signerAttr.ClaimedAttributes)
            {
                foreach (var value in claimedAttr.AttrValues)
                {
                    claimedRoles.Add(DerUtf8String.GetInstance(value).GetString());
                }
            }

            signerRoles = claimedRoles;
        }

        if (signerInformation.UnsignedAttributes != null &&
            signerInformation.UnsignedAttributes[PkcsObjectIdentifiers.IdAASignatureTimeStampToken] != null)
        {
            timeStamp = new TimeStampToken(new CmsSignedData(signerInformation.UnsignedAttributes[PkcsObjectIdentifiers.IdAASignatureTimeStampToken].AttrValues[0].GetEncoded()));
        }

        // Se leen las contrafirmas
        var signers = signerInformation.GetCounterSignatures().GetSigners();

        counterSignatures = new List<SignerInfoNode>();

        foreach (var signer in signers)
        {
            SignerInfoNode node = new SignerInfoNode((SignerInformation)signer, sigDocument);

            counterSignatures.Add(node);
        }

        // Se intenta identificar el certificado empleado para la firma, esto quizás se pueda mejorar
        byte[] certHash = null;
        IssuerSerial issuerSerial = null;

        if (signerInformation.DigestAlgOid == DigestMethod.SHA1.Oid)
        {
            BcCms.Attribute attr = signerInformation.SignedAttributes[PkcsObjectIdentifiers.IdAASigningCertificate];
            SigningCertificate sc = SigningCertificate.GetInstance(attr.AttrValues[0]);
            EssCertID ecid = sc.GetCerts()[0];
            issuerSerial = ecid.IssuerSerial;
            certHash = ecid.GetCertHash();
        }
        else
        {
            BcCms.Attribute attr = signerInformation.SignedAttributes[PkcsObjectIdentifiers.IdAASigningCertificateV2];
            SigningCertificateV2 sc2 = SigningCertificateV2.GetInstance(attr.AttrValues[0]);
            EssCertIDv2 ecid = sc2.GetCerts()[0];
            issuerSerial = ecid.IssuerSerial;
            certHash = ecid.GetCertHash();
        }

        DigestMethod digestMethod = DigestMethod.GetByOid(signerInformation.DigestAlgOid);

        foreach (X509CertificateStructure cs in sigDocument.Certificates)
        {
            if (issuerSerial == null || cs.TbsCertificate.SerialNumber.Equals(issuerSerial.Serial))
            {
                byte[] currentCertHash = digestMethod.CalculateDigest(cs.GetEncoded());

                if (certHash.SequenceEqual(currentCertHash))
                {
                    certificate = new X509Certificate(cs);
                    break;
                }
            }
        }
    }
}
