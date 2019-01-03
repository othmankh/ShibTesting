using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Web.Mvc;
using System.Xml;

namespace SamlProject.Controllers
{
    public class SamlController : Controller
    {
        // GET: Saml
        public string login()
        {
            var x = System.Web.HttpContext.Current.User.Identity as ClaimsIdentity;
            var test = new Test();
            var res = test.ReceiveSamlResponse(Saml2SsoBinding.HttpRedirect, HttpContext);
            var response = test.GetResponse(HttpContext);
            return response.InnerXml + "\n ___________________________________________________________ \n" + x.Name;
        }

        // GET: Saml/Details/5
        public string logout(int id)
        {
            var test = new Test();
            var res = test.ReceiveSamlResponse(Saml2SsoBinding.HttpRedirect, HttpContext);
            return res.ToString();
        }
    }
}
