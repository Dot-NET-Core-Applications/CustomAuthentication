using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;



namespace CustomAuthentication.Models
{
    public class CustomAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
        /// <summary>
        /// <see cref="CustomAuthenticationManager"/>
        /// </summary>
        private readonly ICustomAuthenticationManager customAuthenticationManager;

        public CustomAuthenticationHandler(IOptionsMonitor<BasicAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ICustomAuthenticationManager customAuthenticationManager)
            : base(options, logger, encoder, clock)
        {
            this.customAuthenticationManager = customAuthenticationManager;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (Request.Headers.ContainsKey("Authorization"))
            {
                string authorizationHeader = Request.Headers["Authorization"];
                string token = string.Empty;
                if (string.IsNullOrEmpty(authorizationHeader))
                    return AuthenticateResult.Fail("Unauthorize");
                if (!authorizationHeader.StartsWith("bearer", StringComparison.OrdinalIgnoreCase))
                    return AuthenticateResult.Fail("Unauthorize");
                else
                    token = authorizationHeader.Substring("bearer".Length).Trim();

                if (string.IsNullOrEmpty(token))
                    return AuthenticateResult.Fail("Unauthorize");
                else
                    try
                    {
                        return ValidateToken(token);
                    }
                    catch (Exception)
                    {
                        // Log.
                        return AuthenticateResult.Fail("Unauthorize");
                    }

            }
            return AuthenticateResult.Fail("Unauthorized");
        }

        /// <summary>
        /// Validate request token.
        /// </summary>
        /// <param name="token">Request Authorization token.</param>
        /// <returns><see cref="AuthenticateResult"/></returns>
        private AuthenticateResult ValidateToken(string token)
        {
            KeyValuePair<string, string> validatedToken = customAuthenticationManager.Tokens.FirstOrDefault<KeyValuePair<string, string>>(t => t.Key == token);
            if (validatedToken.Key == token)
            {
                List<Claim> claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, validatedToken.Value),
                };

                ClaimsIdentity identity = new ClaimsIdentity(claims, Scheme.Name);
                GenericPrincipal principal = new GenericPrincipal(identity, null);
                AuthenticationTicket ticket = new AuthenticationTicket(principal, Scheme.Name);
                return AuthenticateResult.Success(ticket);
            }
            return AuthenticateResult.Fail("Unauthorize");
        }
    }
}
