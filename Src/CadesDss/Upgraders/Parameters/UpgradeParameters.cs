using CadesDss.Crypto;
using CadesDss.Helpers;

namespace CadesDss.Upgraders.Parameters;

public class UpgradeParameters
{
    public TimeStampHelpers? TsaClient { get; set; }

    public DigestMethod? DigestMethod { get; set; }
}
