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
using IdentityModel.Client;
using System;

[assembly: OwinStartup(typeof(MvcHybridOwin.Startup))]

namespace MvcHybridOwin
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            AntiForgeryConfig.UniqueClaimTypeIdentifier = IdentityModel.JwtClaimTypes.Name;

            AntiForgeryConfig.SuppressXFrameOptionsHeader = true;

            app.Use<RequireSslMiddleware>();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = Constants.AuthenticationTypeCookies,
                ExpireTimeSpan = new TimeSpan(0, 30, 0),
                SlidingExpiration = true

            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = Constants.ClientCredentials.ClientId,
                Authority = Constants.Endpoints.IdentityServerEndpoint,
                SignInAsAuthenticationType = Constants.AuthenticationTypeCookies,
                ResponseType = string.Join(" ", Constants.OpenIdConnectSettings.ResponseTypes),
                Scope = string.Join(" ", Constants.OpenIdConnectSettings.ScopesRequesting),
                UseTokenLifetime = false,
                //PostLogoutRedirectUri = ""
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

                        if (idTokenHint != null)
                        {
                            context.ProtocolMessage.PostLogoutRedirectUri = appBaseUrl;
                            context.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                        }
                    }
                    await Task.FromResult(context);
                },

                    SecurityTokenValidated = async context =>
                    {
                        var subClaim = context.AuthenticationTicket.Identity.FindFirst(IdentityModel.JwtClaimTypes.Subject);

                        var sidClaim = context.AuthenticationTicket.Identity.FindFirst(IdentityModel.JwtClaimTypes.SessionId);

                        var nameClaim = new Claim(IdentityModel.JwtClaimTypes.Name, $"{Constants.Endpoints.IdentityServerEndpoint}{subClaim.Value}");

                        var givenNameClaim = context.AuthenticationTicket.Identity.FindFirst(IdentityModel.JwtClaimTypes.GivenName);

                        var familyNameClaim = context.AuthenticationTicket.Identity.FindFirst(IdentityModel.JwtClaimTypes.FamilyName);

                        var preferredUserNameClaim = context.AuthenticationTicket.Identity.FindFirst(IdentityModel.JwtClaimTypes.PreferredUserName);

                        var imisbaseAddressClaim = context.AuthenticationTicket.Identity.FindFirst("imisbaseaddress");

                        var imisapiClaim = context.AuthenticationTicket.Identity.FindFirst("imisapi");
                        
                        var newClaimsIdentity = new ClaimsIdentity(context.AuthenticationTicket.Identity.AuthenticationType, IdentityModel.JwtClaimTypes.Name, IdentityModel.JwtClaimTypes.Role);
                        
                        if (subClaim != null) newClaimsIdentity.AddClaim(subClaim);

                        if (sidClaim != null) newClaimsIdentity.AddClaim(sidClaim);

                        if (nameClaim != null) newClaimsIdentity.AddClaim(nameClaim);

                        if (givenNameClaim != null) newClaimsIdentity.AddClaim(givenNameClaim);

                        if (familyNameClaim != null) newClaimsIdentity.AddClaim(familyNameClaim);

                        if (preferredUserNameClaim != null) newClaimsIdentity.AddClaim(preferredUserNameClaim);

                        if (imisbaseAddressClaim != null) newClaimsIdentity.AddClaim(imisbaseAddressClaim);

                        if (imisapiClaim != null) newClaimsIdentity.AddClaim(imisapiClaim);

                        var appBaseUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}";

                        var client = new TokenClient(Constants.Endpoints.TokenEndpoint, Constants.ClientCredentials.ClientId, Constants.ClientCredentials.ClientSecret);

                        var response = await client.RequestAuthorizationCodeAsync(context.ProtocolMessage.Code, appBaseUrl + "/");

                        var expirationDateAsRoundtripString = DateTime.SpecifyKind(DateTime.UtcNow.AddSeconds(response.ExpiresIn), DateTimeKind.Utc).ToString("o");

                        newClaimsIdentity.AddClaim(new Claim("refresh_token", response.RefreshToken));
                        newClaimsIdentity.AddClaim(new Claim("access_token", context.ProtocolMessage.AccessToken));
                        newClaimsIdentity.AddClaim(new Claim("expires_at", expirationDateAsRoundtripString));
                        newClaimsIdentity.AddClaim(new Claim("id_token", response.IdentityToken));
                        
                        context.AuthenticationTicket = new AuthenticationTicket(newClaimsIdentity, context.AuthenticationTicket.Properties);

                        await Task.FromResult(context);
                    }

                    
                }
            });
        }
    }
}