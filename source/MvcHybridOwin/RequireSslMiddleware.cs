using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;

namespace MvcHybridOwin
{
    using AppFunc = Func<IDictionary<string, object>, Task>;
    public class RequireSslMiddleware
    {
        private readonly AppFunc _next;

        public RequireSslMiddleware(AppFunc next)
        {
            _next = next;
        }

        public async Task Invoke(IDictionary<string, object> env)
        {
            var context = new OwinContext(env);

            if (context.Request.Uri.Scheme != Uri.UriSchemeHttps)
            {
                context.Response.StatusCode = 403;
                context.Response.ReasonPhrase = "Ssl is required.";

                await context.Response.WriteAsync(context.Response.ReasonPhrase);

                return;
            }

            await _next(env);
        }
    }


}