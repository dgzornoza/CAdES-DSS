using CadesDss.Signature;
using CadesDss.Upgraders.Parameters;

namespace CadesDss.Upgraders;

internal interface ICadesUpgrader
{
    void Upgrade(SignatureDocument signatureDocument, SignerInfoNode signerInfoNode, UpgradeParameters parameters);
}
