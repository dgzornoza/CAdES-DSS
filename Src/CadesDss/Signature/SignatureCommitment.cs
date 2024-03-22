namespace CadesDss.Signature;

public record SignatureCommitment(SignatureCommitmentType CommitmentType, IEnumerable<string> CommitmentTypeQualifiers);
