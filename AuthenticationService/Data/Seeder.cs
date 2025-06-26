using AuthenticationService.Entities;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace AuthenticationService.Data
{
    public static class Seeder
    {
        public static async Task Seed(AppDbContext dbContext, IConfiguration config, UserManager<AppUser> userManager, RoleManager<IdentityRole<Guid>> roleManager)
        {
            dbContext.Database.EnsureCreated();

            var admin = await userManager.FindByEmailAsync("admin@test.com");
            if (admin == null)
            {
                var result = await userManager.CreateAsync(new AppUser { Email = "admin@test.com", UserName = "admin@test.com", EmailConfirmed = true }, config.GetValue<string>("AdminPassword")!);
                admin = await userManager.FindByEmailAsync("admin@test.com");

                if(admin != null)
                {
                    await roleManager.CreateAsync(new IdentityRole<Guid>("Admin"));
                    await userManager.AddToRoleAsync(admin, "Admin");
                }
            }
        }
    }
}
