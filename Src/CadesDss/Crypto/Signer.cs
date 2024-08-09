using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CadesDss.Crypto;

public class Signer : IDisposable
{
    private bool disposeCryptoProvider;
    private RSA? rsa;
    private bool disposedValue;

    public Signer(X509Certificate2 certificate)
    {
        certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));

        if (!certificate.HasPrivateKey)
        {
            throw new Exception("El certificado no contiene ninguna clave privada");
        }

        SetSigningKey(certificate);
    }

    public byte[]? SignData(byte[] data, DigestMethod digestMethod)
    {
        var hashAlgorithm = digestMethod.GetHashAlgorithmName();
        return rsa?.SignData(data, hashAlgorithm, RSASignaturePadding.Pkcs1);
    }

    private void SetSigningKey(X509Certificate2 certificate)
    {
        var rsa = certificate.GetRSAPrivateKey();
        var key = (rsa as RSACng)?.Key;

        // TODO: esto esta en fase de pruebas, un mismo certificado puede estar con diferentes proveedores en distintas maquinas,
        // es posible que este codigo no se requiera, se mantiene comentado por si en un futuro se tiene que implementar correctamente.
        //if (key?.Provider?.Provider == CryptoConstants.MS_STRONG_PROV ||
        //    key?.Provider?.Provider == CryptoConstants.MS_ENHANCED_PROV ||
        //    key?.Provider?.Provider == CryptoConstants.MS_DEF_PROV ||
        //    key?.Provider?.Provider == CryptoConstants.MS_DEF_RSA_SCHANNEL_PROV)
        //{
        //    // Codigo solo para windows en versiones viejas del framework
        //    // Si se requiere se tiene que implementar en el futuro
        //    throw new NotImplementedException("No se ha implementado el soporte para estos proveedores de certificados");

        //    //Type CspKeyContainerInfo_Type = typeof(CspKeyContainerInfo);

        //    //FieldInfo CspKeyContainerInfo_m_parameters = CspKeyContainerInfo_Type.GetField("m_parameters", BindingFlags.NonPublic | BindingFlags.Instance);
        //    //CspParameters parameters = (CspParameters)CspKeyContainerInfo_m_parameters.GetValue(key.CspKeyContainerInfo);

        //    //var cspparams = new CspParameters(CryptoConst.PROV_RSA_AES, CryptoConst.MS_ENH_RSA_AES_PROV, key.CspKeyContainerInfo.KeyContainerName);
        //    //cspparams.KeyNumber = parameters.KeyNumber;
        //    //cspparams.Flags = parameters.Flags;
        //    //_cryptoProvider = new RSACryptoServiceProvider(cspparams);

        //    //_disposeCryptoProvider = true;
        //}
        //else
        //{
        //    this.rsa = rsa;
        //    disposeCryptoProvider = false;
        //}

        // Codigo del else
        this.rsa = rsa;
        disposeCryptoProvider = false;
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                // dispose managed state (managed objects)
                if (disposeCryptoProvider && rsa != null)
                {
                    rsa.Dispose();
                }
            }

            // free unmanaged resources (unmanaged objects) and override finalizer
            // set large fields to null
            disposedValue = true;
        }
    }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
