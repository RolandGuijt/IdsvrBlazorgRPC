using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityProvider.IdpInMem
{
    public class ConfArchProfileService : IProfileService
    {
        private readonly IUserRepository userRepository;

        public ConfArchProfileService(IUserRepository userRepository)
        {
            this.userRepository = userRepository;
        }
        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var subjectid = context.Subject.GetSubjectId();
            var user = userRepository.GetUserBySubjectId(subjectid);

            var claims = new List<Claim>
            {
                new Claim("employeeno", user.EmployeeNumber.ToString()),
                new Claim("departmentid", user.Department.DepartmentId.ToString())
            };

            context.IssuedClaims = claims.Where(c => context.RequestedClaimTypes.Contains(c.Type)).ToList();
            return Task.CompletedTask;
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            context.IsActive = true;
            return Task.CompletedTask;
        }
    }
}
