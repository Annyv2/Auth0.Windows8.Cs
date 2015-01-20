namespace Auth0.SDK
{
    using System.Linq;
    using System.Threading.Tasks;
    using Windows.Networking.Connectivity;

    public class Device : IDeviceIdProvider
    {
        public Task<string> GetDeviceId()
        {
            var defaultDeviceName = "Windows Device";
            var hostname = NetworkInformation.GetHostNames()
                .FirstOrDefault(name => name.DisplayName.Contains(".local"));

            if (hostname != null)
            {
                defaultDeviceName = hostname.DisplayName.Replace(".local", string.Empty);
            }

            return Task.FromResult<string>(defaultDeviceName);
        }
    }
}
