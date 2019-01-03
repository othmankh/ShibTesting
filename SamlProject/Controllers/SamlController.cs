using Microsoft.AspNetCore.Http;
using System.Web.Mvc;
using System.Xml;

namespace SamlProject.Controllers
{
    public class SamlController : Controller
    {
        // GET: Saml
        public XmlElement login()
        {
            var test = new Test();
            var res = test.ReceiveSamlResponse(HttpContext);
            return res;
        }

        // GET: Saml/Details/5
        public XmlElement logout(int id)
        {
            var test = new Test();
            var res = test.ReceiveSamlResponse(HttpContext);
            return res;
        }
    }
}
