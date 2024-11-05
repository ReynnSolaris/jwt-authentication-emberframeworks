using JWTAuthentication.Framework.Classes;
using JWTAuthentication.Framework.Database;
using JWTAuthentication.Framework.Interfaces;
using JWTAuthentication.Framework.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JWTAuthentication.Controllers
{
    public class TokenInfo
    {
        public string GivenName { get; set; }
        public string Role { get; set; }
        public string Name { get; set; }
    }

        [EnableCors]
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly IUserRepository _userRepository;
        private readonly ITokenService _tokenService;
        private readonly ApplicationDbContext _context;
        private readonly PermissionService _permissionService;

        private readonly SHA_Manager sha = new();

        public TokenInfo ReadTokenInfo(string authorization)
        {
            var token = authorization.Substring("Bearer ".Length).Trim();
            var secretKey = _config["Jwt:Key"];

            var principal = JwtHelper.DecodeJwtToken(token, secretKey);

            if (principal == null)
            {
                return new TokenInfo()
                {
                    GivenName = "",
                    Role = "",
                    Name = ""
                };
            }

            var givenName = JwtHelper.GetClaimValue(principal, ClaimTypes.GivenName);
            var role = JwtHelper.GetClaimValue(principal, ClaimTypes.Role);
            var name = JwtHelper.GetClaimValue(principal, ClaimTypes.Name);

            var result = new TokenInfo()
            {
                GivenName = givenName,
                Role = role,
                Name = name
            };
            return result;
        }

        public AuthenticationController(IConfiguration config, ITokenService tokenService, IUserRepository userRepository, ApplicationDbContext context, PermissionService permissionService)
        {
            _config = config;
            _tokenService = tokenService;
            _userRepository = userRepository;
            _context = context;
            _permissionService = permissionService;
        }

        private UserDTO GetUser(UserModel userModel)
        {
            // Write your code here to authenticate the user     
            return _userRepository.GetUser(userModel);
        }

        // GET api/<AuthenticationController>/5
        [HttpPost("GetToken")]
        public IActionResult Post(UserModel userModel)
        {
            var validUser = GetUser(userModel);
            if (validUser == null)
                return BadRequest();

            var generatedToken = _tokenService.BuildToken(_config["Jwt:Key"], _config["Jwt:Issuer"], validUser);
            if (generatedToken != null)
            {
                validUser.RefreshToken = _tokenService.GenerateRefreshToken();
                validUser.RefreshTokenExpiryTime = DateTime.Now.AddMinutes(1440); // 1 day
                _userRepository.UpdateUser(validUser);

                return Ok(new
                {
                    Token = generatedToken,
                    RefreshToken = validUser.RefreshToken
                });
            }
            return Unauthorized();
        }

        [HttpPost("RefreshToken")]
        public IActionResult Refresh([FromBody] TokenRequest tokenRequest)
        {
            if (tokenRequest is null)
            {
                return BadRequest("Invalid client request");
            }

            string accessToken = tokenRequest.Token;
            string refreshToken = tokenRequest.RefreshToken;

            var principal = GetPrincipalFromExpiredToken(accessToken);
            if (principal == null)
            {
                return BadRequest("Invalid access token or refresh token");
            }

            var userName = principal.Identity.Name;
            var user = _userRepository.GetUser(userName);

            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid access token or refresh token");
            }

            var newAccessToken = _tokenService.BuildToken(_config["Jwt:Key"], _config["Jwt:Issuer"], user);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            _userRepository.UpdateUser(user);

            return Ok(new
            {
                Token = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_config["Jwt:Key"]);

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _config["Jwt:Issuer"],
                ValidAudience = _config["Jwt:Issuer"],
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };

            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha512, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }

    [Authorize(Roles = "developer")]
        [HttpGet()]
        public IActionResult Get()
        {
            return Ok();
        }

        [HttpPost(), Route("CheckToken")]
        public IActionResult CheckPost([FromBody] string token)
        {
            if (_tokenService.ValidateToken(_config["Jwt:Key"].ToString(), _config["Jwt:Issuer"].ToString(), token))
            {
                return Ok();
            }
            return Unauthorized();
        }
        [Authorize(Roles = "Console")]
        [HttpPost("AssignRoleToUser")]
        public IActionResult AssignRoleToUser([FromBody] AssignRoleModel model)
        {
            var user = _context.Users.SingleOrDefault(u => u.UserName == model.UserName);
            var role = _context.Roles.SingleOrDefault(r => r.RoleName == model.RoleName);

            if (user == null || role == null)
            {
                return BadRequest("User or role not found.");
            }

            user.RoleId = role.RoleId;
            _context.SaveChanges();

            return Ok($"Role '{role.RoleName}' assigned to user '{user.UserName}'.");
        }

        [HttpGet("SaltPassword")]
        public IActionResult SaltPassword(string password)
        {
            string salt = "";
            string passwordHash = "";
            if (!string.IsNullOrEmpty(password))
            {
                passwordHash = sha.HashPassword(password, out salt);
            }
            return Ok(new
            {
                passwordHash,
                salt
            });
        }

        [HttpGet("ReadToken")]
        public IActionResult ReadToken([FromHeader] string authorization)
        {
            if (string.IsNullOrEmpty(authorization) || !authorization.StartsWith("Bearer "))
            {
                return BadRequest("Invalid token");
            }

            var token = authorization.Substring("Bearer ".Length).Trim();
            var secretKey = _config["Jwt:Key"];

            var principal = JwtHelper.DecodeJwtToken(token, secretKey);

            if (principal == null)
            {
                return Unauthorized();
            }

            var givenName = JwtHelper.GetClaimValue(principal, ClaimTypes.GivenName);
            var role = JwtHelper.GetClaimValue(principal, ClaimTypes.Role);
            var name = JwtHelper.GetClaimValue(principal, ClaimTypes.Name);

            var result = new
            {
                GivenName = givenName,
                Role = role,
                Name = name
            };

            return Ok(result);
        }

        [HttpPost("ChangePassword")]
        public IActionResult ChangePassword([FromHeader] string authorization, [FromHeader] string token, [FromHeader] string newPassword, [FromHeader] string oldPassword)
        {
            if (!_tokenService.ValidateToken(_config["Jwt:Key"].ToString(), _config["Jwt:Issuer"].ToString(), token))
            {
                System.Diagnostics.Debug.WriteLine("Invalid token");
                return Unauthorized();
            }

            var user = ReadTokenInfo(authorization).Name;

            if (user.IsNullOrEmpty())
            {
                System.Diagnostics.Debug.WriteLine("No user name.");
                return Unauthorized();
            }
                

            var userModel = _context.Users.SingleOrDefault(u => u.UserName.ToLower() == user.ToLower());
            if (userModel == null)
            {
                System.Diagnostics.Debug.WriteLine("No user found.");
                return Unauthorized();
            }
            bool isPasswordValid = sha.VerifyPassword(oldPassword, userModel.Password, userModel.Salt);
            if (!isPasswordValid)
            {
                return Ok(
                        new {
                            msg = "pass_error"
                        }
                    );
            }

            string salt = "";
            string passwordHash = "";
            if (!string.IsNullOrEmpty(newPassword))
            {
                passwordHash = sha.HashPassword(newPassword, out salt);
            } else
            {
                return Ok(
                        new {
                            msg = "pass_notvalid"
                        }
                    );
            }

            userModel.Salt = salt;
            userModel.Password = passwordHash;
            _context.SaveChanges();

            return Ok(
                    new {
                        msg = "pass_changed"
                    }
                );
        }

            // Debug endpoint to get user info and permissions
            [HttpGet("GetUserInfo/")]
        public IActionResult GetUserInfo([FromHeader] string userName, [FromHeader] string token)
        {
            if (!_tokenService.ValidateToken(_config["Jwt:Key"].ToString(), _config["Jwt:Issuer"].ToString(), token))
            {
                return Unauthorized();
            }

            var user = _context.Users
                .Include(u => u.JobTitles)
                .Include(u => u.CurrentAddress)
                .Include(u => u.EmergencyContacts)
                .Include(u => u.PayInformation)
                .Include(u => u.Role)
                    .ThenInclude(r => r.RolePermissions)
                    .ThenInclude(rp => rp.Permission)
                .SingleOrDefault(u => u.UserName.ToLower() == userName.ToLower());

            if (user == null)
            {
                return NotFound("User not found");
            }

            var permissions = _permissionService.GetEffectivePermissions(user.Id);
            var now = DateTime.UtcNow;
            var firstDayOfMonth = new DateTime(now.Year, now.Month, 1);
            var lastDayOfMonth = firstDayOfMonth.AddMonths(1).AddDays(-1);

            // Fetch announcements posted by the user for the current month
            var announcements = _context.System_Announcements
                .Where(a => a.Date_Of_Post >= firstDayOfMonth && a.Date_Of_Post <= lastDayOfMonth)
                .Select(a => new SystemAnnouncementDTO
                {
                    AnnouncementId = a.Announcement_Id,
                    Message = a.Message,
                    Title = a.Title,
                    DateOfPost = a.Date_Of_Post,
                    PosterName = $"{a.Poster.FirstName} " + (a.Poster.PreferredName != "" ? "\""+ a.Poster.PreferredName +"\" " : "") + $"{a.Poster.LastName}",
                    PosterId = a.Poster.Id,
                    Priority = a.Priority
                })
                .ToList();

            var emergencyContacts = _context.EmergencyContacts
                .Where(a => a.UserId == user.Id)
                .Select(a => new EmergencyContactDTO
                {
                    ContactId = a.ContactId,
                    FullName = a.FullName,
                    Phone = a.Phone
                })
                .ToList();

            var userInfo = new UserInfo
            {
                UserId = user.Id,
                UserName = user.UserName,
                FirstName = user.FirstName,
                LastName = user.LastName,
                PreferredName = user.PreferredName,
                RoleName = user.Role.RoleName,
                JobTitle = user.JobTitles?.Name ?? "No job title", // Assuming JobTitleName is a property in JobTitles class
                Permissions = permissions,
                Announcements = announcements,  // Add announcements to the UserInfo object
                HourlyRate = user.PayInformation?.HourlyRate,
                SalaryRate = user.PayInformation?.SalaryRate,
                PositionType = user.PayInformation?.PositionType,
                Address = user.CurrentAddress?.Street != null ? $"{user.CurrentAddress.Street}, {user.CurrentAddress.City} {user.CurrentAddress.State}, {user.CurrentAddress.PostalCode}" : "No address",
                EmergencyContacts = emergencyContacts
            };

            return Ok(userInfo);
        }

        // Debug endpoint to list all roles and their permissions
        [Authorize(Roles = "Console")]
        [HttpGet("ListRolesAndPermissions")]
        public IActionResult ListRolesAndPermissions()
        {
            var roles = _context.Roles.ToList();

            var rolesWithPermissions = roles.Select(role => new
            {
                roleName = role.RoleName,
                permissions = _permissionService.GetRolePermissions(role)
            }).ToList();

            return Ok(rolesWithPermissions);
        }


        public class AssignRoleModel
        {
            public string UserName { get; set; }
            public string RoleName { get; set; }
        }

        public class TokenRequest
        {
            public string Token { get; set; }
            public string RefreshToken { get; set; }
        }
    }
}
