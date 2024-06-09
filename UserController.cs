using Microsoft.AspNetCore.Mvc;
using HarmonyStack_API_ASPNET_.Net.Models;
using MongoDB.Driver;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using HarmonyStack_API_ASPNET_.Net.Services;
using System.Security.Claims;
using System.Security.Cryptography;

[ApiController]
[Route("api/v1")]
public class UserController : ControllerBase
{
    private readonly MongoContext _context;
    private readonly IConfiguration _configuration;
    private readonly HashService _hashService;

    public UserController(MongoContext context, IConfiguration configuration, HashService hashService)
    {
        _context = context;
        _configuration = configuration;
        _hashService = hashService;
    }

    public class UserUpdateModel
    {
        public string? Username { get; set; }
        public string? Lastname { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
        public string? OldPassword { get; set; }
    }

    [HttpGet("user")]
    [UseAuthMiddleware]
    public IActionResult GetUser()
    {
         try
         {
            if (_context == null || _context.Database == null)
            {
                return BadRequest(new { message = "Échec de la connexion à la base de données" });
            }
            var user = HttpContext.Items["User"] as User;
            if (user == null || user.Id == null)
            {
                return Unauthorized(new { message = "Utilisateur non authentifié ou non trouvé." });
            }
            var existUser = _context.Database.GetCollection<User>("users").Find(u => u.Id == user.Id).FirstOrDefault();
            if (existUser == null)
            {
                return Unauthorized(new { message = "Utilisateur non authentifié ou non trouvé." });
            }

            var result = new 
            {
                username = existUser.Username,
                lastname = existUser.Lastname,
                email = existUser.Email
            };

            return Ok(result);
         }
         catch (Exception ex)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new { message = ex.Message });
        }
    }

    [HttpPut("user")]
    [UseAuthMiddleware]
    public IActionResult UpdateUser([FromBody] UserUpdateModel model)
    {
        try
        {
            if (_context == null || _context.Database == null)
            {
                return BadRequest(new { message = "Échec de la connexion à la base de données" });
            }

            if(_hashService == null)
            {
                return BadRequest(new { message = "Échec de la connexion au service" });
            }

            var user = HttpContext.Items["User"] as User;
            if (user == null || user.Id == null)
            {
                return NotFound(new { message = "Utilisateur non trouvé" });
            }

            var updateDefinition = Builders<User>.Update.Set(u => u.Username, model.Username)
                                                        .Set(u => u.Lastname, model.Lastname)
                                                        .Set(u => u.Email, model.Email);

            if (!string.IsNullOrEmpty(model.Password))
            {
                if (string.IsNullOrEmpty(model.OldPassword))
                {
                    return BadRequest(new { message = "Ancien mot de passe requis" });
                }

                var existUser = _context.Database.GetCollection<User>("users").Find(u => u.Id == user.Id).FirstOrDefault();

                if (existUser == null)
                {
                    return NotFound(new { message = "Utilisateur non trouvé" });
                }
                
                var verifyPassword = BCrypt.Net.BCrypt.Verify(model.OldPassword, existUser.Password);
                if (verifyPassword == false)
                {
                    return Unauthorized(new { message = "Mot de passe incorrect" });
                }

                var isSamePassword = BCrypt.Net.BCrypt.Verify(model.Password, existUser.Password);

                if (isSamePassword)
                {
                    return BadRequest(new { message = "Le nouveau mot de passe doit être différent de l'ancien" });
                }

                var hashedPassword = HashService.HashPassword(model.Password);
                updateDefinition = updateDefinition.Set(u => u.Password, hashedPassword);
            }

            _context.Database.GetCollection<User>("users").UpdateOne(u => u.Id == user.Id, updateDefinition);

            return Ok(new { message = "Utilisateur mis à jour avec succès" });
        }
        catch (Exception ex)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new { message = ex.Message });
        }
    }
}
