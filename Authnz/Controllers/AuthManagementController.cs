using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Authnz.Configurations;
using Authnz.Models.DTOs;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;


namespace Authnz.Controllers;
[ApiController]
[Route("[controller]")]
public class AuthManagementController : ControllerBase
{
    private readonly ILogger<AuthManagementController> _logger;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly JwtConfig _jwtConfig;
    
    public AuthManagementController(
        ILogger<AuthManagementController> logger,
        UserManager<IdentityUser> userManager,
        IOptionsMonitor<JwtConfig> optionsMonitor)
    {
        _logger = logger;
        _userManager = userManager;
        _jwtConfig = optionsMonitor.CurrentValue;
    }
    
    
    
    [HttpPost]
    [Route("Register")]
    public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto requestDto)
    {
        if (ModelState.IsValid)
        {
            var emailExist = await _userManager.FindByEmailAsync(requestDto.Email);

            if (emailExist != null)
                return BadRequest("Email already exists");

            var newUser = new IdentityUser()
            {
                Email = requestDto.Email,
                UserName = requestDto.Email,
            };

            var isCreated = await _userManager.CreateAsync(newUser, requestDto.Password);

            if (isCreated.Succeeded)
            {
                // Generate token

                var token = GenerateJwtToken(newUser);
                
                return Ok(new RegistrationRequestResponse()
                {
                    Result = true,
                    Token = token
                });
            }

            return BadRequest( isCreated.Errors.Select(x => x.Description).ToList());

        }
        
        return BadRequest("Invalid request payload");
    }

    [HttpPost]
    [Route("Login")]
    public async Task<IActionResult> Login([FromBody] UserLoginRequestDto requestDto)
    {
        if (ModelState.IsValid)
        {
            var existingUser = await _userManager.FindByEmailAsync(requestDto.Email);

            if (existingUser == null)
                return BadRequest("Invalid Auth");

            var isPasswordValid = await _userManager.CheckPasswordAsync(existingUser, requestDto.Password);

            if (isPasswordValid)
            {
                var token = GenerateJwtToken(existingUser);

                return Ok(new LoginRequestResponse()
                    {
                        Token = token,
                        Result = true
                    }
                );
            }
        }
        return BadRequest("invalid auth");
    }
    
    private string GenerateJwtToken(IdentityUser user)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();

        var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity( new []
            {
                new Claim("Id", user.Id),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            }),
            Expires = DateTime.UtcNow.AddHours(4),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha512)
        };

        var token = jwtTokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = jwtTokenHandler.WriteToken(token);

        return jwtToken;
    }
    
}