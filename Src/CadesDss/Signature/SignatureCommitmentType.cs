using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Esf;

namespace CadesDss.Signature;

public record SignatureCommitmentType(DerObjectIdentifier Oid)
{
    public static SignatureCommitmentType ProofOfOrigin => new(CommitmentTypeIdentifier.ProofOfOrigin);
    public static SignatureCommitmentType ProofOfReceipt => new(CommitmentTypeIdentifier.ProofOfReceipt);
    public static SignatureCommitmentType ProofOfDelivery => new(CommitmentTypeIdentifier.ProofOfDelivery);
    public static SignatureCommitmentType ProofOfSender => new(CommitmentTypeIdentifier.ProofOfSender);
    public static SignatureCommitmentType ProofOfApproval => new(CommitmentTypeIdentifier.ProofOfApproval);
    public static SignatureCommitmentType ProofOfCreation => new(CommitmentTypeIdentifier.ProofOfCreation);
}
