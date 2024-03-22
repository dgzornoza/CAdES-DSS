using System.Security.Cryptography.X509Certificates;

namespace CadesDss.Helpers
{
    public static class CertificateHelpers
    {
        public static X509Chain GetCertificateChain(X509Certificate2 certificate, X509Certificate2[] certificates = null)
        {
            var chain = new X509Chain();

            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreWrongUsage;

            if (certificates != null)
            {
                chain.ChainPolicy.ExtraStore.AddRange(certificates);
            }

            if (!chain.Build(certificate))
            {
                throw new Exception("No se puede construir la cadena de certificación");
            }

            return chain;
        }

        /// <summary>
        /// Selecciona un certificado del almacén de certificados
        /// </summary>
        /// <returns></returns>
        public static X509Certificate2 SelectCertificate(string message = null, string title = null)
        {
            X509Certificate2 cert = null;

            try
            {
                // Open the store of personal certificates.
                var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                X509Certificate2Collection collection = store.Certificates;
                X509Certificate2Collection fcollection = collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

                if (string.IsNullOrEmpty(message))
                {
                    message = "Seleccione un certificado.";
                }

                if (string.IsNullOrEmpty(title))
                {
                    title = "Firmar archivo";
                }

                X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(fcollection, title, message, X509SelectionFlag.SingleSelection);

                if (scollection != null && scollection.Count == 1)
                {
                    cert = scollection[0];

                    if (cert.HasPrivateKey == false)
                    {
                        throw new Exception("El certificado no tiene asociada una clave privada.");
                    }
                }

                store.Close();
            }
            catch (Exception ex)
            {
                // Thx @rasputino
                throw new Exception("No se ha podido obtener la clave privada.", ex);
            }

            return cert;
        }
    }
}
