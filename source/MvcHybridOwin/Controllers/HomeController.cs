using System.Net.Http;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using System.Threading.Tasks;
using System.Linq;
using System.Globalization;
using System;
using IdentityModel.Client;

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


            var expiresAtFromClaims = DateTime.Parse(ClaimsPrincipal.Current.FindFirst("expires_at").Value, null, DateTimeStyles.RoundtripKind);

            var accessToken = string.Empty;

            if (DateTime.Now.ToUniversalTime() < expiresAtFromClaims)
            {
            accessToken = ClaimsPrincipal.Current.FindFirst("access_token").Value;
            }
            else
            {
                var tokenClient = new TokenClient(Constants.Endpoints.TokenEndpoint, Constants.ClientCredentials.ClientId, Constants.ClientCredentials.ClientSecret);
                var tresponse = await tokenClient.RequestRefreshTokenAsync(ClaimsPrincipal.Current.FindFirst("refresh_token").Value);
                if (!tresponse.IsError)
                {
                    accessToken = tresponse.AccessToken;

                    var result = from c in ClaimsPrincipal.Current.Claims
                                 where c.Type != "access_token" && c.Type != "refresh_token" && c.Type != "expires_at" && c.Type != "id_token"
                                 select c;
                    var cs = result.ToList();

                    var expirationDateAsRoundtripString = DateTime.SpecifyKind(DateTime.UtcNow.AddSeconds(tresponse.ExpiresIn), DateTimeKind.Utc).ToString("o");


                    cs.Add(new Claim("refresh_token", tresponse.RefreshToken));
                    cs.Add(new Claim("access_token", accessToken));
                    cs.Add(new Claim("expires_at", expirationDateAsRoundtripString));

                    var newIdentity = new ClaimsIdentity(cs, "Cookies", IdentityModel.JwtClaimTypes.Name, IdentityModel.JwtClaimTypes.Role);

                    Request.GetOwinContext().Authentication.SignIn(newIdentity);

                    
                }
                else
                {
                    Request.GetOwinContext().Authentication.SignOut();
                    return Redirect("/");
                }

            }
                        
            client.SetBearerToken(accessToken);            
            var resp = await client.GetAsync($"Party/{claim.Value}");
            var content = await resp.Content.ReadAsStringAsync();

            ViewBag.Data = content;

            return View();

        }

        public ActionResult Signout()
        {
            Request.GetOwinContext().Authentication.SignOut();
            return Redirect("/");
        }

        public void SignoutCleanup(string sid)
        {
            var cp = (ClaimsPrincipal)User;
            var sidClaim = cp.FindFirst("sid");
            if(sidClaim != null && sidClaim.Value == sid)
            {
                Request.GetOwinContext().Authentication.SignOut("Cookies");
            }            
        }
    }
}