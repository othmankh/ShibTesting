using System.Web;
using System.Xml;

namespace SamlProject
{
    public interface IProvideSaml2Service
    {
        void SendAuthnRequest(string idpLocation, Saml2SsoBinding idpBinding,
            string fromSpEntityId, string returnUrl, HttpContextBase httpContext);

        XmlElement ReceiveSamlResponse( HttpContextBase httpContext);
    }
}