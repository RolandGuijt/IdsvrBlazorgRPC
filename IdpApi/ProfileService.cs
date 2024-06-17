using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityProvider
{
    public class ProfileService : IProfileService
    {
        private readonly IUserRepository _UserRepository;

        public ProfileService(IUserRepository userRepository)
        {
            _UserRepository = userRepository;
        }
        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var claims = context.Subject.Claims;

            var user = _UserRepository.GetUserBySubjectId(context.Subject.GetSubjectId());

            var allClaims = claims.Concat(new Claim[] {
                new Claim("employeeno", $"{user.EmployeeNumber}"),
                new Claim("departmentid", $"{user.Department.DepartmentId}")
            });

            var filteredClaims = allClaims.Where(c => context.RequestedClaimTypes.Contains(c.Type));
            context.IssuedClaims.AddRange(filteredClaims);
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            context.IsActive = true;
            return Task.CompletedTask;
        }
    }
}
