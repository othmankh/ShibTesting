using System.Web.Mvc;

namespace SamlProject.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var test = new Test();
            var idpLocation = "https://auth.bathspa.ac.uk/idp/profile/SAML2/Redirect/SSO";
            var entityId = "unitu.co.uk";
            test.SendAuthnRequest(idpLocation, Saml2SsoBinding.HttpRedirect, entityId, entityId, HttpContext);
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}
