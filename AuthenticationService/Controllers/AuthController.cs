using AuthenticationService.DTOs;
using AuthenticationService.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
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
        private readonly IConfiguration _configuration;

        public AuthController(SignInManager<AppUser> signInManager, 
            RoleManager<IdentityRole<Guid>> roleManager,
            UserManager<AppUser> userManager,
            IConfiguration configuration)
        {
            _signInManager = signInManager;
            _roleManager = roleManager;
            _userManager = userManager;
            _configuration = configuration;
        }

        [AllowAnonymous]
        [HttpPost("~/custom-register")]
        public async Task<IActionResult> Register(DTOs.CustomRegisterRequest request)
        {
            if (await _userManager.FindByNameAsync(request.UserName) != null)
                return BadRequest("This username is already taken");

            var user = new AppUser
            {
                Email = request.Email,
                UserName = request.UserName,
                FirstName = request.FirstName,
                LastName = request.LastName,
            };
            var result = await _userManager.CreateAsync(user, request.Password);

            if(!result.Succeeded) return BadRequest(result);
            return Ok(result);
        }

        [AllowAnonymous]
        [HttpPost("~/custom-login")]
        public async Task<IActionResult> Login(LoginRequest request)
        {
            // validate request
            if (request == null || string.IsNullOrEmpty(request.Password) || string.IsNullOrEmpty(request.Email))
                return BadRequest("Invalid login details");

            // get user
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null) return BadRequest("Invalid login details");

            // check password
            if(!await _userManager.CheckPasswordAsync(user, request.Password))
                return BadRequest("Invalid login details");

            // issue token
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.GivenName, user.FirstName),
                new Claim(JwtRegisteredClaimNames.FamilyName, user.LastName),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName),
                new Claim(JwtRegisteredClaimNames.Email, user.Email)
            };

            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));
            var credential = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                //audience: "",
                signingCredentials: credential,
                claims: claims,
                expires: DateTime.Now.AddHours(1)
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return Ok(new {token = jwt});
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
