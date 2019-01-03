using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Xml;
using ComponentSpace.SAML2.Assertions;
using ComponentSpace.SAML2.Bindings;
using ComponentSpace.SAML2.Profiles.SSOBrowser;
using ComponentSpace.SAML2.Protocols;

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

            var privateKey = @"MIIDUDCCAjgCCQDZl9Be7/58pTANBgkqhkiG9w0BAQsFADBqMQswCQYDVQQGEwJH QjERMA8GA1UECAwIU29tZXJzZXQxDTALBgNVBAcMBEJhdGgxHDAaBgNVBAoME0Jh dGggU3BhIFVuaXZlcnNpdHkxGzAZBgNVBAMMEmF1dGguYmF0aHNwYS5hYy51azAe Fw0xNzA2MTIxMjMxMjNaFw0zNzA2MDcxMjMxMjNaMGoxCzAJBgNVBAYTAkdCMREw DwYDVQQIDAhTb21lcnNldDENMAsGA1UEBwwEQmF0aDEcMBoGA1UECgwTQmF0aCBT cGEgVW5pdmVyc2l0eTEbMBkGA1UEAwwSYXV0aC5iYXRoc3BhLmFjLnVrMIIBIjAN BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw54yhGaNi9/5YADBiGWn33YcQNAI f6jagUt7uc/XTcTMoHrirLNftACRzhLXS049fwe48EC6xITe5PWNbiglEXyLmnBF KMOCN7dXDCPWKhSe9vBA2b6+2BS22jAi255WhDj65u4j1+Rg5i0r5E/YLwvG5YAw i9aKSHvvwFwy8Gwo7O3viMqlKsIKx+VV3SfC70NhvtCPh1aHbECfXr05kx5KYXnO UZRZHVLdzG9XP1+BawFcY+kFcflK9uNHUD/i36gCO0X2KciwWWHrmI5ZSR4tymUv FYAIiPklFReOqXUgj0v8pS/NqxKrRzZZWPwbTieJBS0GTt6YvCrQZVnzXQIDAQAB MA0GCSqGSIb3DQEBCwUAA4IBAQBO7NZbRXUfdaICB33BuAwOxsaXaSBkEI6tgZLx wAI/gmOEy639DxWGFuhoUeMhl9B3w5COes7VNvgy9Dl/QaZLH9p3pTBwtc92nN2J U3S4MPdGhtXXKud2DiQuGYtTnp48wbphfAGQDKhz6RI3gionZyHBOkV6Fx5XvSVj Oa7DRfawg951TKGP3OpKI4vuY3kb4hW7XEFfcCEQOcaCujckSwxU6QaI7DnDGP+O wdBmfdEj9Ey37nM0qrzI5cjTz51xJ9c0oNd3+abiGzzL7L7N+AfRVcECowo5l63j vNXAI2IiTocKRsZIWg8qn0pFts3vr7afzJMY6ZQsISwD4fLg";
            var bytes = privateKey.GetType();
            // Send the authentication request to the identity provider over the configured binding.
            switch (idpBinding)
            {
                case Saml2SsoBinding.HttpPost:
                    ServiceProvider.SendAuthnRequestByHTTPPost(httpContext.Response, idpLocation, authnRequestXml, relayState);
                    httpContext.Response.End();
                    break;

                case Saml2SsoBinding.HttpRedirect:
                    var encryptionCertificate = new X509Certificate2();
                    //var encryptionCertificate = GetCertificate();
                    encryptionCertificate.Import(Encoding.ASCII.GetBytes(privateKey));
                    ServiceProvider.SendAuthnRequestByHTTPRedirect(httpContext.Response, idpLocation, authnRequestXml, relayState,
                        encryptionCertificate.PrivateKey);
                    break;

                default:
                    throw new NotSupportedException(string.Format(
                        "The binding is currently not supported."));
            }
        }

        public ComponentSpaceSaml2Response ReceiveSamlResponse(Saml2SsoBinding spBinding, HttpContextBase httpContext)
        {
            XmlElement responseElement; string relayState;
            var encryptionCertificate = new X509Certificate2();
            //var encryptionCertificate = GetCertificate();
            var privateKey = @"MIIDUDCCAjgCCQC+yzvBEnTI0DANBgkqhkiG9w0BAQsFADBqMQswCQYDVQQGEwJH QjERMA8GA1UECAwIU29tZXJzZXQxDTALBgNVBAcMBEJhdGgxHDAaBgNVBAoME0Jh dGggU3BhIFVuaXZlcnNpdHkxGzAZBgNVBAMMEmF1dGguYmF0aHNwYS5hYy51azAe Fw0xNzA2MTIxMjMyMDlaFw0zNzA2MDcxMjMyMDlaMGoxCzAJBgNVBAYTAkdCMREw DwYDVQQIDAhTb21lcnNldDENMAsGA1UEBwwEQmF0aDEcMBoGA1UECgwTQmF0aCBT cGEgVW5pdmVyc2l0eTEbMBkGA1UEAwwSYXV0aC5iYXRoc3BhLmFjLnVrMIIBIjAN BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6ZwPWSXGxtfgSBlFSIE7XGwtKSgM AOFw0r/8XstAyBdthJmTAUg0pgJAuh2IPCf3/+T/mypDMfE9cGg53KEqk8aKyoDF KSbEjGDGDu3viBLVNjA7tu1qBsN/MGuG2bWO/RwqVH1XV52nvibw19tOOL6alxW4 7JGApo/4rU4uZJrkjQA/qqy1xnmep6vGmJn5r3c+eJzicZ2PUE+srInj2mh7M4Cd CXK/d1pCHlDeXpd2qldva6h1i6GShop1K4uIUG5qLw6tzVxO28RxU9hakF4jsIAJ ML1V5suV13F1x3BflosrH7vlmtBwgiuwGizLbp53HzHYyaePeo9JkIAVJwIDAQAB MA0GCSqGSIb3DQEBCwUAA4IBAQC0yXqEa0JFL7t4rREhJRylusn5kze8vDXsBq2T 84JjRR5v3Hf+N4iVc4k9UQi10SWsG91IPhD3gow5pI/36w2fLQlATj23YoBw1TpZ UoMNyhS/NZSRk+VJOBo+y6UpB1axk1ClvcanC4xSisgzHL70R3D/Z0ikfZ7df76r XcxVll30Ip+ywjWAvgpuEhXXgdXYD3r+lb8VRSGFAn0gd3nQMYbSXWBY4rWeHa9e aKUKWhZ11zY7fcPFsMnNQfZ43sHqnZovelOX7/CdD0CYfXvBJY5wadpowr906WPx UaPVPqo6jGwPYAhUMZjLzttfgPl3FZ61NHJNwdpaBYZ7BuLQ";
            encryptionCertificate.Import(Encoding.ASCII.GetBytes(privateKey));
            ServiceProvider.ReceiveSAMLResponseByHTTPPost(httpContext.Request, out responseElement, out relayState);
            var info = new ComponentSpaceSaml2Response(responseElement, relayState, spBinding,
               encryptionCertificate, httpContext);
            return info;
        }

    }
}