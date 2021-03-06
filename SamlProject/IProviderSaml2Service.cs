﻿using System.Web;

namespace SamlProject
{
    public interface IProvideSaml2Service
    {
        void SendAuthnRequest(string idpLocation, Saml2SsoBinding idpBinding,
            string fromSpEntityId, string returnUrl, HttpContextBase httpContext);

        ComponentSpaceSaml2Response ReceiveSamlResponse(Saml2SsoBinding spBinding, HttpContextBase httpContext);
    }
}