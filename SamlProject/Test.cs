using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Xml;
using ComponentSpace.SAML2.Assertions;
using ComponentSpace.SAML2.Bindings;
using ComponentSpace.SAML2.Profiles.SSOBrowser;
using ComponentSpace.SAML2.Protocols;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

namespace SamlProject
{
    // ReSharper disable ClassNeverInstantiated.Global
    public class Test : IProvideSaml2Service
    // ReSharper restore ClassNeverInstantiated.Global
    {
        //private readonly IStoreSamlCertificates _certificates;

        //public Test(IStoreSamlCertificates certificatesStore)
        //{
        //    _certificates = certificatesStore;
        //}

        //private X509Certificate2 GetCertificate()
        //{
        //    var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        //    try
        //    {
        //    //< add key = "SamlTestServiceProviderEntityId" value = "https://develop.ucosmic.com/sign-on/saml/2" />
        //    //< add key = "SamlTestCertificateThumbprint" value = "1945D599DF7F3B3D6513C87A8CDDF4CE6E0899B6" />
        //              store.Open(OpenFlags.ReadOnly);
        //        var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, "1945D599DF7F3B3D6513C87A8CDDF4CE6E0899B6", false);
        //        if (certificates.Count < 1)
        //        {
        //            throw new InvalidOperationException(string.Format(
        //                "Could not find certificate with thumbprint '{0}' in My LocalMachine store.",
        //                    "1945D599DF7F3B3D6513C87A8CDDF4CE6E0899B6"));
        //        }
        //        return certificates[0];
        //    }
        //    finally
        //    {
        //        store.Close();
        //    }
        //}

        public void SendAuthnRequest(string idpLocation, Saml2SsoBinding idpBinding,
            string fromSpEntityId, string returnUrl, HttpContextBase httpContext)
        {
            // Create the authentication request.
            var authnRequest = new AuthnRequest
            {
                Destination = idpLocation,
                Issuer = new Issuer(fromSpEntityId),
                ForceAuthn = true,
                NameIDPolicy = new NameIDPolicy(null, null, true),
            };

            // Serialize the authentication request to XML for transmission.
            var authnRequestXml = authnRequest.ToXml();

            // Don't sign if using HTTP redirect as the generated query string is too long for most browsers.
            //if (idpBinding != Saml2SsoBinding.HttpRedirect)
            //{
            //    // Sign the authentication request.
            //    var signingCertificate = _certificates.GetSigningCertificate();
            //    SAMLMessageSignature.Generate(authnRequestXml, signingCertificate.PrivateKey, signingCertificate);
            //}

            // Create and cache the relay state so we remember which SP resource the user wishes to access after SSO.
            //SAML.HttpContext = httpContext;
            string relayState = null;
            if (!string.IsNullOrWhiteSpace(returnUrl))
                relayState = RelayStateCache.Add(new RelayState(returnUrl, null));
            
            // Send the authentication request to the identity provider over the configured binding.
            switch (idpBinding)
            {
                case Saml2SsoBinding.HttpPost:
                    ServiceProvider.SendAuthnRequestByHTTPPost(httpContext.Response, idpLocation, authnRequestXml, relayState);
                    httpContext.Response.End();
                    break;

                case Saml2SsoBinding.HttpRedirect:
                   
                    StreamReader sr = new StreamReader(@"C:\Users\vladi\Source\Repos\othmankh\ShibTesting\SamlProject\App_Data\encrypted_private_key.pem");
                    PemReader pr = new PemReader(sr, new PasswordFinder("WRONG_PASSWORD"));
                    RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)pr.ReadObject());

                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    rsa.ImportParameters(rsaParams);

                    var encryptionCertificate = new X509Certificate2();
                    encryptionCertificate.Import(@"C:\Users\vladi\Source\Repos\othmankh\ShibTesting\SamlProject\App_Data\unitu.cer");
                    encryptionCertificate.PrivateKey = rsa;

                    ServiceProvider.SendAuthnRequestByHTTPRedirect(httpContext.Response, idpLocation, authnRequestXml, relayState, encryptionCertificate.PrivateKey);
                    break;

                default:
                    throw new NotSupportedException(string.Format(
                        "The binding is currently not supported."));
            }
        }

        public void ReceiveSamlResponse(Saml2SsoBinding spBinding, HttpContextBase httpContext)
        {
            XmlElement responseElement; string relayState;
            ServiceProvider.ReceiveSAMLResponseByHTTPPost(httpContext.Request, out responseElement, out relayState);
            //var info = new ComponentSpaceSaml2Response(responseElement, relayState, spBinding,
            //    _certificates.GetEncryptionCertificate(), httpContext);
            //return info;
        }

    }

    public class PasswordFinder : IPasswordFinder
    {
        private string Password = String.Empty;

        public PasswordFinder(string password)
        {
            this.Password = password;
        }

        public char[] GetPassword()
        {
            return Password.ToCharArray();
        }
    }
    
}

