namespace Auth0.SDK
{
    using System;

    public class AuthenticationErrorException : Exception
    {
        public AuthenticationErrorException()
        {
        }

        public AuthenticationErrorException(string message) : base(message)
        {
        }
    }
}