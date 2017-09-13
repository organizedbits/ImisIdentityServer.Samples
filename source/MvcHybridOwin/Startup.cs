using System.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Helpers;
using System.Collections.Generic;
using Microsoft.Owin.Security;
using Microsoft.IdentityModel.Protocols;

[assembly: OwinStartup(typeof(MvcHybridOwin.Startup))]

namespace MvcHybridOwin
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();
            AntiForgeryConfig.UniqueClaimTypeIdentifier = Constants.OpenIdConnectSettings.ClaimTypeNames.Subject;
            AntiForgeryConfig.SuppressXFrameOptionsHeader = true;
            
            app.Use<RequireSslMiddleware>();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = Constants.AuthenticationTypeCookies,
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = Constants.ClientCredentials.ClientId,
                ClientSecret = Constants.ClientCredentials.ClientSecret,
                Authority = Constants.Endpoints.IdentityServerEndpoint,
                SignInAsAuthenticationType = Constants.AuthenticationTypeCookies,
                ResponseType = string.Join(" ", Constants.OpenIdConnectSettings.ResponseTypes),
                Scope = string.Join(" ", Constants.OpenIdConnectSettings.ScopesRequesting),

                ProtocolValidator = new OpenIdConnectProtocolValidator
                {
                    RequireNonce = true,
                },

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = async context =>
                    {
                        var appBaseUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}";
                        if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.AuthenticationRequest)
                        {
                            context.ProtocolMessage.RedirectUri = $"{appBaseUrl}/";
                        }

                        if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                        {
                            var idTokenHint = context.OwinContext.Authentication.User.FindFirst("id_token");

                            if(idTokenHint != null)
                            {
                                context.ProtocolMessage.PostLogoutRedirectUri = appBaseUrl;
                                context.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                            }

                        }
                        await Task.FromResult(context);
                    },

                    SecurityTokenValidated = async context =>
                    {
                        var nid = new ClaimsIdentity(context.AuthenticationTicket.Identity.AuthenticationType, IdentityModel.JwtClaimTypes.GivenName, IdentityModel.JwtClaimTypes.Role);

                        nid.AddClaims(context.AuthenticationTicket.Identity.Claims);

                        //var accessToken = new Claim("access_token", context.ProtocolMessage.AccessToken);

                        var idToken = new Claim("id_token", context.ProtocolMessage.IdToken);

                       // nid.AddClaim(accessToken);
                        nid.AddClaim(idToken);

                        context.AuthenticationTicket = new AuthenticationTicket(nid, context.AuthenticationTicket.Properties);
                        await Task.FromResult(context);
                    }
                }
            });
        }
    }
}