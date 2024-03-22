using CadesDss.Crypto;
using CadesDss.Signature;

namespace CadesDss.Validation;

public class CadesValidator
{
    public ValidationResult Validate(SignerInfoNode signerNode)
    {
        ValidationResult result = new();

        try
        {
            if (!signerNode.SignerInformation.Verify(signerNode.Certificate))
            {
                result.IsValid = false;
                result.Message = "La verificación de la firma no ha sido satisfactoria";

                return result;
            }

            if (signerNode.TimeStamp != null)
            {
                DigestMethod tokenDigestMethod = DigestMethod.GetByOid(signerNode.TimeStamp.TimeStampInfo.HashAlgorithm.ObjectID.Id);
                byte[] signatureValueHash = tokenDigestMethod.CalculateDigest(signerNode.SignerInformation.GetSignature());

                if (!signerNode.TimeStamp.TimeStampInfo.GetMessageImprintDigest().SequenceEqual(signatureValueHash))
                {
                    result.IsValid = false;
                    result.Message = "La huella del sello de tiempo no se corresponde con la calculada";

                    return result;
                }
            }

            result.IsValid = true;
            result.Message = "Verificación de la firma satisfactoria";

        }
        catch (Exception ex)
        {
            result.IsValid = false;
            result.Message = ex.Message;
        }

        return result;
    }
}
