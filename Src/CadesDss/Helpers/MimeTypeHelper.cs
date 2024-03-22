namespace CadesDss.Helpers;

internal static class MimeTypeHelper
{
    private static string _defaultOid = "1.2.840.113549.1.7.1";

    private static Dictionary<string, string> _mimeTypes = new()
    {
        {"application/pdf", "1.2.840.10003.5.109.1"},
        {"application/postscript", "1.2.840.10003.5.109.2"},
        {"text/html", "1.2.840.10003.5.109.3"},
        {"image/tiff", "1.2.840.10003.5.109.4"},
        {"image/gif", "1.2.840.10003.5.109.5"},
        {"image/jpeg", "1.2.840.10003.5.109.6"},
        {"image/png", "1.2.840.10003.5.109.7"},
        {"video/mpeg", "1.2.840.10003.5.109.8"},
        {"text/sgml", "1.2.840.10003.5.109.9"},
        {"text/xml", "1.2.840.10003.5.109.10"},
        {"application/msword", "1.2.840.113556.4.2"},
        {"application/vnd.ms-excel", "1.2.840.113556.4.3"},
        {"application/vnd.ms-project", "1.2.840.113556.4.4"},
        {"application/vnd.ms-powerpoint", "1.2.840.113556.4.5"},
        {"application/vnd.ms-works", "1.2.840.113556.4.6"}
    };

    public static string GetMimeTypeOid(string mimeType)
    {
        if (_mimeTypes.ContainsKey(mimeType))
        {
            return _mimeTypes[mimeType];
        }
        else
        {
            return _defaultOid;
        }
    }
}
