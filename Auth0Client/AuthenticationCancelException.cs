namespace Auth0.SDK
{
    using System;

    public class AuthenticationCancelException : Exception
    {
        public AuthenticationCancelException()
        { 
        }

        public AuthenticationCancelException(string message) : base(message)
        {
        }
    }
}