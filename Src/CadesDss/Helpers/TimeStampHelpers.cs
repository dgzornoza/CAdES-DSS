using CadesDss.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using System.Net;
using System.Text;

namespace CadesDss.Helpers;

public class TimeStampHelpers
{
    private string url;
    private string? user;
    private string? password;

    public TimeStampHelpers(string url)
    {
        this.url = url;
    }

    public TimeStampHelpers(string url, string user, string password)
        : this(url)
    {
        this.user = user;
        this.password = password;
    }


    /// <summary>
    /// Realiza la petición de sellado del hash que se pasa como parametro y devuelve la
    /// respuesta del servidor.
    /// </summary>
    /// <param name="hash"></param>
    /// <param name="digestMethod"></param>
    /// <param name="certReq"></param>
    /// <returns></returns>
    public byte[] GetTimeStamp(byte[] hash, DigestMethod digestMethod, bool certReq)
    {
        TimeStampRequestGenerator tsrq = new TimeStampRequestGenerator();
        tsrq.SetCertReq(certReq);

        BigInteger nonce = BigInteger.ValueOf(DateTime.Now.Ticks);

        TimeStampRequest tsr = tsrq.Generate(digestMethod.Oid, hash, nonce);
        byte[] data = tsr.GetEncoded();

        HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
        req.Method = "POST";
        req.ContentType = "application/timestamp-query";
        req.ContentLength = data.Length;

        if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(password))
        {
            string auth = string.Format("{0}:{1}", user, password);
            req.Headers["Authorization"] = "Basic " + Convert.ToBase64String(Encoding.Default.GetBytes(auth), Base64FormattingOptions.None);
        }

        Stream reqStream = req.GetRequestStream();
        reqStream.Write(data, 0, data.Length);
        reqStream.Close();

        HttpWebResponse res = (HttpWebResponse)req.GetResponse();
        if (res.StatusCode != HttpStatusCode.OK)
        {
            throw new Exception("El servidor ha devuelto una respuesta no válida");
        }
        else
        {
            Stream resStream = new BufferedStream(res.GetResponseStream());
            TimeStampResponse tsRes = new TimeStampResponse(resStream);
            resStream.Close();

            tsRes.Validate(tsr);

            if (tsRes.TimeStampToken == null)
            {
                throw new Exception("El servidor no ha devuelto ningún sello de tiempo");
            }

            return tsRes.TimeStampToken.GetEncoded();
        }
    }
}
