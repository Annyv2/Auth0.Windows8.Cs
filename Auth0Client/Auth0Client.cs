using System.Linq;
using Windows.Devices.Enumeration;
using Windows.Networking.Connectivity;

namespace Auth0.SDK
{
    using Newtonsoft.Json.Linq;
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Http;
    using System.Threading.Tasks;
    using Windows.Security.Authentication.Web;

    /// <summary>
    /// A simple client to Authenticate Users with Auth0.
    /// </summary>
    public partial class Auth0Client
    {
        private const string AuthorizeUrl = "https://{0}/authorize?client_id={1}&redirect_uri={2}&response_type=token&connection={3}&scope={4}";
        private const string LoginWidgetUrl = "https://{0}/login/?client={1}&redirect_uri={2}&response_type=token&scope={3}";
        private const string DeviceQueryString = "&device={0}";
        private const string ResourceOwnerEndpoint = "https://{0}/oauth/ro";
        private const string DelegationEndpoint = "https://{0}/delegation";
        private const string UserInfoEndpoint = "https://{0}/userinfo?access_token={1}";
        private const string DefaultCallback = "https://{0}/mobile";

        private readonly string _domain;
        private readonly string _clientId;
        private readonly string _device;

        public Auth0Client(string domain, string clientId)
        {
            _domain = domain;
            _clientId = clientId;
        }

        public Auth0Client(string domain, string clientId, string device)
            : this(domain, clientId)
        {
            _device = device;
        }

        public Auth0User CurrentUser { get; private set; }

        public string DeviceName
        {
            get
            {
                if (!String.IsNullOrEmpty(_device))
                    return _device;

                var defaultDeviceName = "Windows Device";
                var hostname = NetworkInformation.GetHostNames()
                    .FirstOrDefault(name => name.DisplayName.Contains(".local"));
                if (hostname != null)
                    defaultDeviceName = hostname.DisplayName.Replace(".local", "");
                return defaultDeviceName;
            }
        }

        public string CallbackUrl
        {
            get
            {
                return string.Format(DefaultCallback, this._domain);
            }
        }

        /// <summary>
        /// Login a user into an Auth0 application by showing an embedded browser window either showing the widget or skipping it by passing a connection name.
        /// </summary>
        /// <param name="connection">Optional. Connection name to bypass the login widget</param>
        /// <param name="scope">Optional. Scope indicating what attributes are needed. "openid" to just get the user_id or "openid profile" to get back everything.
        /// <remarks>When using openid profile if the user has many attributes the token might get big and the embedded browser (Internet Explorer) won't be able to parse a large URL</remarks>
        /// </param>
        /// <returns>Returns a Task of Auth0User</returns>
        public async Task<Auth0User> LoginAsync(string connection = "", string scope = "openid")
        {
            var tcs = new TaskCompletionSource<Auth0User>();
            var auth = await this.GetAuthenticatorAsync(connection, scope);

            if (auth.ResponseStatus == WebAuthenticationStatus.Success)
            {
                this.SetupCurrentUser(parseResult(auth.ResponseData));
                tcs.TrySetResult(this.CurrentUser);
            }

            return this.CurrentUser;
        }

        /// <summary>
        ///  Log a user into an Auth0 application given an user name and password.
        /// </summary>
        /// <returns>Task that will complete when the user has finished authentication.</returns>
        /// <param name="connection">The name of the connection to use in Auth0. Connection defines an Identity Provider.</param>
        /// <param name="userName">User name.</param>
        /// <param name="password">User password.</param>
        /// <param name="scope">Optional. Scope indicating what attributes are needed. "openid" to just get the user_id or "openid profile" to get back everything.
        /// <remarks>When using openid profile if the user has many attributes the token might get big and the embedded browser (Internet Explorer) won't be able to parse a large URL</remarks>
        /// </param>
        /// <returns>Returns a Task of Auth0User</returns>
        public Task<Auth0User> LoginAsync(string connection, string userName, string password, string scope = "openid")
        {
            var endpoint = string.Format(ResourceOwnerEndpoint, this._domain);
            var parameters = new Dictionary<string, string> 
			{
				{ "client_id", this._clientId },
				{ "connection", connection },
				{ "username", userName },
				{ "password", password },
				{ "grant_type", "password" },
				{ "scope", scope }
			};

            if (RequireDevice(scope))
                parameters.Add("device", DeviceName);

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
        /// Get a delegation token.
        /// </summary>
        /// <returns>Delegation token result.</returns>
        /// <param name="targetClientId">Target client ID.</param>
        /// <param name="options">Custom parameters.</param>
        public Task<JObject> GetDelegationToken(string targetClientId, IDictionary<string, string> options = null)
        {
            var id_token = string.Empty;
            options = options ?? new Dictionary<string, string>();

            // ensure id_token
            if (options.ContainsKey("id_token"))
            {
                id_token = options["id_token"];
                options.Remove("id_token");
            }
            else
            {
                id_token = this.CurrentUser.IdToken;
            }

            if (string.IsNullOrEmpty(id_token))
            {
                throw new InvalidOperationException(
                    "You need to login first or specify a value for id_token parameter.");
            }

            var endpoint = string.Format(DelegationEndpoint, this._domain);
            var parameters = new Dictionary<string, string> 
			{
				{ "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer" },
				{ "id_token", id_token },
				{ "target", targetClientId },
				{ "client_id", this._clientId }
			};

            // custom parameters
            foreach (var option in options)
            {
                parameters.Add(option.Key, option.Value);
            }

            var request = new HttpClient();
            return request.PostAsync(new Uri(endpoint), new FormUrlEncodedContent(parameters)).ContinueWith(t =>
            {
                try
                {
                    var text = t.Result.Content.ReadAsStringAsync().Result;
                    return JObject.Parse(text);
                }
                catch (Exception)
                {
                    throw;
                }
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
            var endpoint = string.Format(UserInfoEndpoint, this._domain, accountProperties["access_token"]);
            var request = new HttpClient();

            request.GetAsync(new Uri(endpoint)).ContinueWith(t =>
            {
                try
                {
                    t.Result.EnsureSuccessStatusCode();
                    var profileString = t.Result.Content.ReadAsStringAsync().Result;
                    accountProperties.Add("profile", profileString);
                }
                catch (Exception ex)
                {
                    throw ex;
                }
                finally
                {
                    this.CurrentUser = new Auth0User(accountProperties);
                }
            })
            .Wait();
        }

        private async Task<WebAuthenticationResult> GetAuthenticatorAsync(string connection, string scope)
        {
            // Generate state to include in startUri
            var chars = new char[16];
            var rand = new Random();
            for (var i = 0; i < chars.Length; i++)
            {
                chars[i] = (char)rand.Next((int)'a', (int)'z' + 1);
            }

            // Encode scope value
            scope = WebUtility.UrlEncode(scope);

            var redirectUri = this.CallbackUrl;
            var authorizeUri = !string.IsNullOrWhiteSpace(connection) ?
                string.Format(AuthorizeUrl, this._domain, this._clientId, Uri.EscapeDataString(redirectUri), connection, scope) :
                string.Format(LoginWidgetUrl, this._domain, this._clientId, Uri.EscapeDataString(redirectUri), scope);

            if (RequireDevice(scope))
                authorizeUri += String.Format(DeviceQueryString, Uri.EscapeDataString(DeviceName));

            var state = new string(chars);
            var startUri = new Uri(authorizeUri + "&state=" + state);
            var endUri = new Uri(redirectUri);

            return await WebAuthenticationBroker.AuthenticateAsync(WebAuthenticationOptions.None, startUri, endUri).AsTask<WebAuthenticationResult>();
        }

        private static bool RequireDevice(string scope)
        {
            return !String.IsNullOrEmpty(scope) && scope.Contains("offline_access");
        }

        private static Dictionary<string, string> parseResult(string result)
        {
            var tokens = new Dictionary<string, string>();

            // Result will be: https://callback#id_token=1234&access_token=12345&...
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
