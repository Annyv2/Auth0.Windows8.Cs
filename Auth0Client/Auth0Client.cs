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
        private const string AuthorizeUrl =
            "https://{0}/authorize?client_id={1}&redirect_uri={2}&response_type=token&connection={3}&scope={4}";

        private const string LoginWidgetUrl =
            "https://{0}/login/?client={1}&redirect_uri={2}&response_type=token&scope={3}";

        private const string ResourceOwnerEndpoint = "https://{0}/oauth/ro";
        private const string DelegationEndpoint = "https://{0}/delegation";
        private const string UserInfoEndpoint = "https://{0}/userinfo?access_token={1}";
        private const string DefaultCallback = "https://{0}/mobile";

        private readonly string domain;
        private readonly string clientId;

        public Auth0Client(string domain, string clientId)
        {
            this.domain = domain;
            this.clientId = clientId;
            this.DeviceIdProvider = new Device();
        }

        public Auth0User CurrentUser { get; private set; }

        public string CallbackUrl
        {
            get { return string.Format(DefaultCallback, this.domain); }
        }

        /// <summary>
        /// The component used to generate the device's unique id
        /// </summary>
        public IDeviceIdProvider DeviceIdProvider { get; set; }

        /// <summary>
        /// Login a user into an Auth0 application. Attempts to do a background login, but if unsuccessful shows an embedded browser window either showing the widget or skipping it by passing a connection name
        /// </summary>
        /// <param name="connection">Optional connection name to bypass the login widget</param>
        /// <param name="withRefreshToken">true to include the refresh_token in the response, false (default) otherwise.
        /// The refresh_token allows you to renew the id_token indefinitely (does not expire) unless specifically revoked.</param>
        /// <param name="scope">Optional scope, either 'openid' or 'openid profile'</param>
        /// <returns>Returns a Task of Auth0User</returns>
        public async Task<Auth0User> LoginAsync(string connection = "", bool withRefreshToken = false, string scope = "openid")
        {
            scope = IncreaseScopeWithOfflineAccess(withRefreshToken, scope);

            var tcs = new TaskCompletionSource<Auth0User>();

            var auth = await this.GetAuthenticatorAsync(connection, scope);
            if (auth.ResponseStatus == WebAuthenticationStatus.Success)
            {
                var tokens = ParseResult(auth.ResponseData);
                if (tokens != null)
                {
                    this.SetupCurrentUser(tokens);
                    tcs.TrySetResult(this.CurrentUser);
                }
                else
                {
                    throw new AuthenticationErrorException();
                }
            }
            else if (auth.ResponseStatus == WebAuthenticationStatus.UserCancel)
            {
                throw new AuthenticationCancelException();
            }

            return this.CurrentUser;
        }

        /// <summary>
        ///  Log a user into an Auth0 application given an user name and password.
        /// </summary>
        /// <returns>Task that will complete when the user has finished authentication.</returns>
        /// <param name="connection" type="string">The name of the connection to use in Auth0. Connection defines an Identity Provider.</param>
        /// <param name="userName" type="string">User name.</param>
        /// <param name="password" type="string">User password.</param>
        /// <param name="withRefreshToken">true to include the refresh_token in the response, false otherwise.
        /// The refresh_token allows you to renew the id_token indefinitely (does not expire) unless specifically revoked.</param>
        /// <param name="scope">Scope.</param>
        public async Task<Auth0User> LoginAsync(string connection, string userName, string password, bool withRefreshToken = false, string scope = "openid")
        {
            scope = IncreaseScopeWithOfflineAccess(withRefreshToken, scope);

            var endpoint = string.Format(ResourceOwnerEndpoint, this.domain);
            var parameters = new Dictionary<string, string>
            {
                {"client_id", this.clientId},
                {"connection", connection},
                {"username", userName},
                {"password", password},
                {"grant_type", "password"},
                {"scope", scope}
            };

            if (scope.Contains("offline_access"))
            {
                var deviceId = Uri.EscapeDataString(await this.DeviceIdProvider.GetDeviceId());
                parameters.Add("device", deviceId);
            }

            var request = new HttpClient();
            var result = await request.PostAsync(new Uri(endpoint), new FormUrlEncodedContent(parameters));

            try
            {
                result.EnsureSuccessStatusCode();
                var text = result.Content.ReadAsStringAsync().Result;
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
                    throw new UnauthorizedAccessException(
                        "Expected access_token in access token response, but did not receive one.");
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

            return this.CurrentUser;
        }

        /// <summary>
        /// Renews the idToken (JWT)
        /// </summary>
        /// <returns>The refreshed token.</returns>
        /// <param name="refreshToken">The refresh token</param>
        /// <param name="options">Additional parameters.</param>
        public async Task<JObject> RefreshToken(string refreshToken = "", Dictionary<string, string> options = null)
        {
            var emptyToken = string.IsNullOrEmpty(refreshToken);
            if (emptyToken && (this.CurrentUser == null || string.IsNullOrEmpty(this.CurrentUser.RefreshToken)))
            {
                throw new InvalidOperationException(
                    "The current user's refresh_token could not be retrieved and no refresh_token was provided as parameter");
            }

            return await this.GetDelegationToken(
                api: "app",
                refreshToken: emptyToken ? this.CurrentUser.RefreshToken : refreshToken,
                options: options);
        }

        /// <summary>
        /// Verifies if the jwt for the current user has expired.
        /// </summary>
        /// <returns>true if the token has expired, false otherwise.</returns>
        /// <remarks>Must be logged in before invoking.</remarks>
        public bool HasTokenExpired()
        {
            if (string.IsNullOrEmpty(this.CurrentUser.IdToken))
            {
                throw new InvalidOperationException("You need to login first.");
            }

            return TokenValidator.HasExpired(this.CurrentUser.IdToken);
        }

        /// <summary>
        /// Renews the idToken (JWT)
        /// </summary>
        /// <returns>The refreshed token.</returns>
        /// <remarks>The JWT must not have expired.</remarks>
        /// <param name="options">Additional parameters.</param>
        public Task<JObject> RenewIdToken(Dictionary<string, string> options = null)
        {
            if (string.IsNullOrEmpty(this.CurrentUser.IdToken))
            {
                throw new InvalidOperationException("You need to login first.");
            }

            options = options ?? new Dictionary<string, string>();

            if (!options.ContainsKey("scope"))
            {
                options["scope"] = "passthrough";
            }

            return this.GetDelegationToken(
                api: "app",
                idToken: this.CurrentUser.IdToken,
                options: options);
        }

        /// <summary>
        /// Get a delegation token
        /// </summary>
        /// <returns>Delegation token result.</returns>
        /// <param name="api">The type of the API to be used.</param>
        /// <param name="idToken">The string representing the JWT. Useful only if not expired.</param>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="targetClientId">The clientId of the target application for which to obtain a delegation token.</param>
        /// <param name="options">Additional parameters.</param>
        public Task<JObject> GetDelegationToken(string api = "", string idToken = "", string refreshToken = "", string targetClientId = "", Dictionary<string, string> options = null)
        {
            if (!(string.IsNullOrEmpty(idToken) || string.IsNullOrEmpty(refreshToken)))
            {
                throw new InvalidOperationException(
                    "You must provide either the idToken parameter or the refreshToken parameter, not both.");
            }

            if (string.IsNullOrEmpty(idToken) && string.IsNullOrEmpty(refreshToken))
            {
                if (this.CurrentUser == null || string.IsNullOrEmpty(this.CurrentUser.IdToken))
                {
                    throw new InvalidOperationException(
                    "You need to login first or specify a value for idToken or refreshToken parameter.");
                }

                idToken = this.CurrentUser.IdToken;
            }

            options = options ?? new Dictionary<string, string>();
            options["id_token"] = idToken;
            options["api_type"] = api;
            options["refresh_token"] = refreshToken;
            options["target"] = targetClientId;

            var endpoint = string.Format(DelegationEndpoint, this.domain);
            var parameters = new Dictionary<string, string>
            {
                {"grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
                {"target", targetClientId},
                {"client_id", this.clientId}
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

        private static string IncreaseScopeWithOfflineAccess(bool withRefreshToken, string scope)
        {
            if (withRefreshToken && !scope.Contains("offline_access"))
            {
                scope += " offline_access";
            }

            return scope;
        }

        private void SetupCurrentUser(IDictionary<string, string> accountProperties)
        {
            var endpoint = string.Format(UserInfoEndpoint, this.domain, accountProperties["access_token"]);
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
            var authorizeUri = !string.IsNullOrWhiteSpace(connection)
                ? string.Format(AuthorizeUrl, this.domain, this.clientId, Uri.EscapeDataString(redirectUri),
                    connection,
                    scope)
                : string.Format(LoginWidgetUrl, this.domain, this.clientId, Uri.EscapeDataString(redirectUri), scope);

            if (scope.Contains("offline_access"))
            {
                var deviceId = Uri.EscapeDataString(await this.DeviceIdProvider.GetDeviceId());
                authorizeUri += string.Format("&device={0}", deviceId);
            }

            var state = new string(chars);
            var startUri = new Uri(authorizeUri + "&state=" + state);
            var endUri = new Uri(redirectUri);

            return await WebAuthenticationBroker.AuthenticateAsync(WebAuthenticationOptions.None, startUri, endUri);
        }

        private static bool RequireDevice(string scope)
        {
            return !String.IsNullOrEmpty(scope) && scope.Contains("offline_access");
        }

        /// <summary>
        /// After authenticating the result will be: https://callback#id_token=1234&access_token=12345&...
        /// </summary>
        /// <param name="result"></param>
        /// <returns></returns>
        private static Dictionary<string, string> ParseResult(string result)
        {
            if (String.IsNullOrEmpty(result) || !result.Contains("#"))
                return null;

            var tokens = new Dictionary<string, string>();

            foreach (var tokenPart in result.Split('#')[1].Split('&'))
            {
                var tokenKeyValue = tokenPart.Split('=');
                tokens.Add(tokenKeyValue[0], tokenKeyValue[1]);
            }

            return tokens;
        }
    }
}