using AuthenticationService.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace AuthenticationService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly SignInManager<AppUser> _signInManager;
        private readonly RoleManager<IdentityRole<Guid>> _roleManager;
        private readonly UserManager<AppUser> _userManager;

        public AuthController(SignInManager<AppUser> signInManager, RoleManager<IdentityRole<Guid>> roleManager, UserManager<AppUser> userManager)
        {
            _signInManager = signInManager;
            _roleManager = roleManager;
            _userManager = userManager;
        }

        [HttpPost]
        [Route("~/logout")]
        public async Task<IActionResult> Logout(object empty)
        {
            if(empty != null)
            {
                await _signInManager.SignOutAsync();
                return Ok(new { message = "Logged out successfully" });
            }
            return Unauthorized();
        }

        [HttpPost("~/roles")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AddRole(string roleName)
        {
            await _roleManager.CreateAsync(new IdentityRole<Guid>(roleName));
            return Ok();
        }

        [HttpPost("~/roles/users/{userId}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AddUserToRole(string roleName, Guid userId)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if(user == null)
            {
                return BadRequest();
            }

            var role = await _roleManager.FindByNameAsync(roleName);
            if(role == null) await _roleManager.CreateAsync(new IdentityRole<Guid>(roleName));
            await _userManager.AddToRoleAsync(user, roleName);

            return Ok();
        }

        [HttpPost("~/roles/users/{userId}/remove")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> RemoveUserFromRole(string roleName, Guid userId)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
            {
                return BadRequest();
            }

            if(await _userManager.IsInRoleAsync(user, roleName))
            {
                await _userManager.RemoveFromRoleAsync(user, roleName);
            }

            return Ok();
        }
    }
}
