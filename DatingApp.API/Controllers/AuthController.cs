using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository repo;
        private readonly string key;

        public IConfiguration Config { get; }

        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            this.Config = config;
            this.repo = repo;
            this.key = config.GetSection("AppSettings:Token").Value; 
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
            if (await repo.UserExists(userForRegisterDto.UserName.ToLower()))
                return BadRequest("User Already Exists");
            var userToCreate = new User() { UserName = userForRegisterDto.UserName.ToLower() };
            
            var createdUser = await repo.Register(userToCreate, userForRegisterDto.Password);
            return StatusCode(201);
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            var user = await repo.Login(userForLoginDto.UserName, userForLoginDto.Password);
            if (user == null)
                return Unauthorized();
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()),
                new Claim(ClaimTypes.Name,user.UserName),
            };

            var symmetricKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(this.key));
            var creds=new SigningCredentials(symmetricKey,SecurityAlgorithms.HmacSha512Signature);
            
            var tokenDescriptor = new SecurityTokenDescriptor(){
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds,
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return Ok(new {
                token=tokenHandler.WriteToken(token),
                });
        }
    }
}