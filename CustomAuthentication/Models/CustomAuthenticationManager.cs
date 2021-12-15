using System;
using System.Collections.Generic;
using System.Linq;

namespace CustomAuthentication.Models
{
    public class CustomAuthenticationManager : ICustomAuthenticationManager
    {
        /// <summary>
        /// List of user credentials.
        /// </summary>
        private readonly IDictionary<string, string> users;

        /// <summary>
        /// Dictionary mapping of tokens with usernames.
        /// </summary>
        private readonly IDictionary<string, string> tokens;

        public IDictionary<string, string> Tokens => tokens;

        /// <summary>
        /// Instance of CustomAuthenticationManager.
        /// </summary>
        /// <param name="users">Dictionary of users.</param>
        /// <param name="tokens">Mapping list of tokens to usernames.</param>
        public CustomAuthenticationManager(IDictionary<string, string> users, IDictionary<string, string> tokens)
        {
            this.users = users;
            this.tokens = tokens;
        }

        /// <summary>
        /// Authenticate user.
        /// </summary>
        /// <param name="username">Username.</param>
        /// <param name="password">Password.</param>
        /// <returns>Custom token string.</returns>
        public string Authenticate(string username, string password)
        {
            if (users.Any<KeyValuePair<string, string>>(user => user.Key.Equals(username) && user.Value.Equals(password)))
            {
                var token = Guid.NewGuid().ToString() + "-" + users[username].GetHashCode();
                tokens.Add(token, username);
                return token;
            }
            return default;
        }
    }
}
