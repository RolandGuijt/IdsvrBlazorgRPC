using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Blazor.Pages
{
    public class LoginModel : PageModel
    {
        public async Task OnGet()
        {
            await HttpContext.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, 
                new AuthenticationProperties { RedirectUri = "/" });
        }
    }
}
