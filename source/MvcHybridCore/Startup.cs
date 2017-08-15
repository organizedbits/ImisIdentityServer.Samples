using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.IdentityModel.Tokens.Jwt;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace MvcHybridCore
{
    public class Startup
    {
        
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            app.UseDeveloperExceptionPage();

            app.UseStaticFiles();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationScheme =  "Cookies",
                AutomaticAuthenticate = true,
                ExpireTimeSpan = TimeSpan.FromMinutes(60),
                CookieName = "mvchybridcore"

            });

            JwtSecurityTokenHandler.DefaultInboundClaimFilter.Clear();

            app.UseOpenIdConnectAuthentication(new OpenIdConnectOptions
            {
                AuthenticationScheme = "oidc",
                SignInScheme = "Cookies",
                Authority = "https://ffapp2.advsolhosting.net/imisidentityserver/identity/",
                RequireHttpsMetadata = true,
                ClientId = "externalmvcowinhybrid-hf",
                ClientSecret = "makeyoursecretunique",
                ResponseType =  "code id_token",
                Scope = {"openid","offline_access","imisapi"},
                GetClaimsFromUserInfoEndpoint = false,
                SaveTokens = true,
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = JwtClaimTypes.Name,
                    RoleClaimType = JwtClaimTypes.Role
                }
            });

            app.UseMvcWithDefaultRoute();

        }
    }
}
