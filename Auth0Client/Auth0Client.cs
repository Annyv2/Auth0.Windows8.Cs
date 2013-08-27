using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Windows.Security.Authentication.Web;
using System.Net.Http;
using Windows.Foundation;
using Windows.UI.Xaml;

namespace Auth0.SDK
{
    /// <summary>
    /// A simple client to Authenticate Users with Auth0.
    /// </summary>
    public partial class Auth0Client
    {
        private const string AuthorizeUrl = "https://{0}.auth0.com/authorize?client_id={1}&scope=openid%20profile&redirect_uri={2}&response_type=token&connection={3}";
        private const string LoginWidgetUrl = "https://{0}.auth0.com/login/?client={1}&scope=openid%20profile&redirect_uri={2}&response_type=token";
        private const string ResourceOwnerEndpoint = "https://{0}.auth0.com/oauth/ro";
        private const string DefaultCallback = "https://{0}.auth0.com/mobile";

        private readonly string subDomain;
        private readonly string clientId;
        private readonly string clientSecret;

        public Auth0Client(string subDomain, string clientId, string clientSecret)
        {
            this.subDomain = subDomain;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }

        public Auth0User CurrentUser { get; private set; }

        public string CallbackUrl
        {
            get
            {
                return string.Format(DefaultCallback, this.subDomain);
            }
        }

        /// <summary>
        /// Login a user into an Auth0 application by showing an embedded browser window either showing the widget or skipping it by passing a connection name
        /// </summary>
        /// <param name="owner">The owner window</param>
        /// <param name="connection">Optional connection name to bypass the login widget</param>
        /// <param name="scope">Optional. Scope indicating what attributes are needed. "openid" to just get the user_id or "openid profile" to get back everything.
        /// <remarks>When using openid profile if the user has many attributes the token might get big and the embedded browser (Internet Explorer) won't be able to parse a large URL</remarks>
        /// </param>
        /// <returns>Returns a Task of Auth0User</returns>
        public Task<Auth0User> LoginAsync(UIElement owner, string connection = "")
        {
            var tcs = new TaskCompletionSource<Auth0User>();
            var auth = this.GetAuthenticator(connection);

            if (auth.Result.ResponseStatus == WebAuthenticationStatus.Success)
            {
                this.SetupCurrentUser(parseResult(auth.Result.ResponseData));
                tcs.TrySetResult(this.CurrentUser);
            }

            return tcs.Task;
        }

        /// <summary>
        ///  Log a user into an Auth0 application given an user name and password.
        /// </summary>
        /// <returns>Task that will complete when the user has finished authentication.</returns>
        /// <param name="connection" type="string">The name of the connection to use in Auth0. Connection defines an Identity Provider.</param>
        /// <param name="userName" type="string">User name.</param>
        /// <param name="password type="string"">User password.</param>
        public Task<Auth0User> LoginAsync(string connection, string userName, string password)
        {
            var endpoint = string.Format(ResourceOwnerEndpoint, this.subDomain);
            var parameters = new Dictionary<string, string> 
			{
				{ "client_id", this.clientId },
				{ "client_secret", this.clientSecret },
				{ "connection", connection },
				{ "username", userName },
				{ "password", password },
				{ "grant_type", "password" },
				{ "scope", "openid profile" }
			};

            var request = new HttpClient();
            return request.PostAsync(new Uri(endpoint), new FormUrlEncodedContent(parameters)).ContinueWith(t =>
            {
                try
                {
                    t.Result.EnsureSuccessStatusCode();
                    var text = t.Result.Content.ReadAsStringAsync().Result;
                    var data = JObject.Parse(text).ToObject<Dictionary<string, string>>();

                    if (data.ContainsKey("error"))
                    {
                        throw new UnauthorizedAccessException("Error authenticating: " + data["error"]);
                    }
                    else if (data.ContainsKey("access_token"))
                    {
                        this.SetupCurrentUser(data);
                    }
                    else
                    {
                        throw new UnauthorizedAccessException("Expected access_token in access token response, but did not receive one.");
                    }
                }
                catch (Exception ex)
                {
                    throw ex;
                }

                return this.CurrentUser;
            });
        }

        /// <summary>
        /// Log a user out of a Auth0 application.
        /// </summary>
        public void Logout()
        {
            this.CurrentUser = null;
        }

        private void SetupCurrentUser(IDictionary<string, string> accountProperties)
        {
            this.CurrentUser = new Auth0User(accountProperties);
        }

        private Task<WebAuthenticationResult> GetAuthenticator(string connection)
        {
            // Generate state to include in startUri
            var chars = new char[16];
            var rand = new Random();
            for (var i = 0; i < chars.Length; i++)
            {
                chars[i] = (char)rand.Next((int)'a', (int)'z' + 1);
            }

            var redirectUri = this.CallbackUrl;
            var authorizeUri = !string.IsNullOrWhiteSpace(connection) ?
                string.Format(AuthorizeUrl, subDomain, clientId, Uri.EscapeDataString(redirectUri), connection) :
                string.Format(LoginWidgetUrl, subDomain, clientId, Uri.EscapeDataString(redirectUri));

            var state = new string(chars);
            var startUri = new Uri(authorizeUri + "&state=" + state);
            var endUri = new Uri(redirectUri);

            return WebAuthenticationBroker.AuthenticateAsync(WebAuthenticationOptions.None, startUri, endUri).AsTask<WebAuthenticationResult>();
        }

        private static Dictionary<string, string> parseResult(string result)
        {
            Dictionary<string, string> tokens = new Dictionary<string, string>();

            //result will be: https://callback#id_token=1234&access_token=12345&...
            var strTokens = result.Split('#')[1].Split('&');

            foreach (var t in strTokens)
            {
                var tok = t.Split('=');
                tokens.Add(tok[0], tok[1]);
            }

            return tokens;
        }
    }
}
