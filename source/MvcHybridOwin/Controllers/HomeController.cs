using System.Net.Http;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using System.Threading.Tasks;
using System.Linq;

namespace MvcHybridOwin.Controllers
{
   [Authorize]
    public class HomeController : Controller
    {
        [HttpGet]
        [Authorize]
        public ActionResult Index()
        {

            var endPoint = ClaimsPrincipal.Current.Claims.Single(c => c.Type == "imisbaseaddress");

            ViewBag.Origin = endPoint;

            return View();
        }

        [HttpPost]
        public ActionResult Index2()
        {
            return View("Index");
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

        public ActionResult Claims()
        {
            ViewBag.Message = "Claims";

            return View();
        }

        public async Task<ActionResult> Proxy()
        {

            var claim = ClaimsPrincipal.Current.Claims.Single(c => c.Type == "sub");

            var endPoint = ClaimsPrincipal.Current.Claims.Single(c => c.Type == "imisapi").Value;
            
            var client = new HttpClient();
            client.BaseAddress = new System.Uri(endPoint);
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
            var accessToken = ClaimsPrincipal.Current.FindFirst("access_token");
            client.SetBearerToken(accessToken.Value);            
            var resp = await client.GetAsync($"Party/{claim.Value}");
            var content = await resp.Content.ReadAsStringAsync();

            ViewBag.Data = content;

            return View();

        }

        public ActionResult LogOut()
        {
            Request.GetOwinContext().Authentication.SignOut();
            return Redirect("/");
        }

        public ActionResult LocalLogout()
        {
            Request.GetOwinContext().Authentication.SignOut();
            return Redirect("/");
        }
    }
}