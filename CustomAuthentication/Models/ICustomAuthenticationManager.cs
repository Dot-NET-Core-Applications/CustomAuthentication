using System;
using System.Collections.Generic;

namespace CustomAuthentication.Models
{
    public interface ICustomAuthenticationManager
    {
        /// <summary>
        /// Authenticate user.
        /// </summary>
        /// <param name="name">Username.</param>
        /// <param name="password">Password.</param>
        /// <returns>Token string.</returns>
        string Authenticate(string name, string password);

        /// <summary>
        /// Mapping list of token to usernames.
        /// </summary>
        IDictionary<string, string> Tokens { get; }
    }
}
