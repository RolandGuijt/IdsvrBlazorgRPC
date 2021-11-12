using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using System.Threading.Tasks;

namespace IdentityProvider.IdpInMem
{
    public class ConfArchProfileService : IProfileService
    {
        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            return Task.CompletedTask;
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            return Task.CompletedTask;
        }
    }
}
