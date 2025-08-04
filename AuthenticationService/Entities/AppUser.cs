using Microsoft.AspNetCore.Identity;

namespace AuthenticationService.Entities
{
    public class AppUser : IdentityUser<Guid>
    {
        [PersonalData]
        public string FirstName { get; set; }
        [PersonalData]
        public string LastName { get; set; }
    }
}
