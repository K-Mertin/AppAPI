using Microsoft.AspNetCore.Mvc;
using DatingApp.API.Data;
using System.Threading.Tasks;
using DatingApp.API.Models;
using DatingApp.API.Dtos;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System;
using Microsoft.Extensions.Configuration;
using AutoMapper;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly IAuthRepository _repo;
        private readonly IMapper _mapper;
        private readonly IConfiguration _config;

        public AuthController(IAuthRepository repo, IMapper mapper, IConfiguration config)
        {
            _repo = repo;
            _mapper = mapper;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody]UserForRegisterDto userFroRegisterDto)
        {
            if (!string.IsNullOrEmpty(userFroRegisterDto.Username))
                userFroRegisterDto.Username = userFroRegisterDto.Username.ToLower();

            if (await _repo.UserExists(userFroRegisterDto.Username))
                ModelState.AddModelError("Username", "Username already exists");

            //validate request
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userToCreate = new User
            {
                Username = userFroRegisterDto.Username
            };

            var createUser = await _repo.Register(userToCreate, userFroRegisterDto.Password);

            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody]UserForLoginDto userForLoginDto)
        {
            var userFromRepo = await _repo.Login(userForLoginDto.Username, userForLoginDto.Password);

            if (userFromRepo == null)
                return Unauthorized();

            //generate token
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_config.GetSection("AppSetting:Token").Value);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                    new Claim(ClaimTypes.Name, userFromRepo.Username)
                }),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha512Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            var user = _mapper.Map<UserForListDto>(userFromRepo);

            return Ok(new { tokenString, user });
        }
    }
}