using System;


namespace CustomAuthentication.Models
{
    public class UserCredential
    {
        public UserCredential(string username, string password)
        {
            Username = username;
            Password = password;
        }

        /// <summary>
        /// Username.
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// Password.
        /// </summary>
        public string Password { get; set; }
    }
}
