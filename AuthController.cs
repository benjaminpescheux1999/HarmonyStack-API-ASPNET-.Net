using Microsoft.AspNetCore.Mvc;
using HarmonyStack_API_ASPNET_.Net.Models;
using MongoDB.Driver;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using HarmonyStack_API_ASPNET_.Net.Services;
using System.Security.Claims;

[ApiController]
[Route("api/v1")]
public class AuthController : ControllerBase
{
    private readonly MongoContext _context;
    private readonly IConfiguration _configuration;
    private readonly HashService _hashService;

    // Constructor for the AuthController
    public AuthController(MongoContext context, IConfiguration configuration, HashService hashService)
    {
        _context = context;
        _configuration = configuration;
        _hashService = hashService;
    }
    public class SignupModel : User
    {
        public string? PasswordConfirmation { get; set; }
    }

    // Signup method
    [HttpPost("signup")]
    public IActionResult Signup([FromBody] SignupModel user)
    {
        try
        {

            if (_context == null || _context.Database == null)
            {
            return BadRequest(new { message = "Échec de la connexion à la base de données" });
            }
            // Check if the user has filled all the fields
            if (user.Email == null || user.Password == null || user.Username == null || user.Lastname == null || user.PasswordConfirmation == null)
            {
                return BadRequest(new { message = "Tous les champs sont requis" });
            }
            // Check if the password and the password confirmation are the same
            if(user.Password != user.PasswordConfirmation)
            {
                return BadRequest(new { message = "Le mot de passe et la confirmation de mot de passe ne correspondent pas" });
            }
            // Check if the user already exists
            var existingUser = _context.Database.GetCollection<User>("users").Find(u => u.Email == user.Email).FirstOrDefault();
            if (existingUser != null)
            {
                return BadRequest(new { message = "Un utilisateur avec cette adresse email existe déjà" });
            }
            // Hash the password
            var hashedPassword = HashService.HashPassword(user.Password);
            var newuser = new User
            {
                Email = user.Email,
                Password = hashedPassword,
                Username = user.Username,
                Lastname = user.Lastname
            };
            // Insert the new user in the database
            _context.Database.GetCollection<User>("users").InsertOne(newuser);

            // Check if the user has been created
            if(newuser.Id == null)
            {
                return BadRequest(new { message = "L'utilisateur n'existe pas ou l'ID est nul" });
            }
            // Generate the XSRF token
            var xsrfToken = HashService.GenerateXsrfToken();
            // Generate the access token
            var accessToken = GenerateJwtToken(newuser.Id.ToString(), xsrfToken);
            // Generate the refresh token
            var refreshToken = HashService.GenerateBase64RefreshToken();

            var refreshTokenCollection = _context.Database.GetCollection<RefreshToken>("refreshtokens");
            var filter = Builders<RefreshToken>.Filter.Eq(rt => rt.UserId, newuser.Id);
            var update = Builders<RefreshToken>.Update
                .Set(rt => rt.Token, refreshToken)
                .SetOnInsert(rt => rt.CreatedAt, DateTime.UtcNow)
                .Set(rt => rt.UpdatedAt, DateTime.UtcNow);
            var options = new UpdateOptions { IsUpsert = true };
            // Upsert the refresh token in the database
            refreshTokenCollection.UpdateOne(filter, update, options);

            // Return the access token/refresh token in the cookies and the user data
            Response.Cookies.Append("access_token", accessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                MaxAge = TimeSpan.FromHours(1),
                SameSite = SameSiteMode.Strict,
                Path = "/"
            });
            Response.Cookies.Append("refresh_token", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                MaxAge = TimeSpan.FromDays(365),
                Path = "/",
                SameSite = SameSiteMode.Strict
            });
            return Ok(new {
                accessTokenExpiresIn = TimeSpan.FromHours(1).TotalMilliseconds,
                refreshTokenExpiresIn = TimeSpan.FromDays(365).TotalMilliseconds,
                xsrfToken,
                user = new { newuser.Id, newuser.Username, newuser.Email, newuser.Lastname }
            });
        }
        catch (Exception ex)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new { message = ex.Message });
        }
    }

    // Login method
    [HttpPost("login")]
    public IActionResult Login([FromBody] User loginModel)
    {
        try
        {
            if (_context == null || _context.Database == null)
            {
                return BadRequest(new { message = "Échec de la connexion à la base de données" });
            }

            // Check if the password is not empty
            if (loginModel.Password == null){ 
                return BadRequest(new { message = "Le mot de passe ne peut pas être vide" });
            }
            // Generate the XSRF token
            var xsrfToken = HashService.GenerateXsrfToken();
            // Generate the refresh token
            var refreshToken = HashService.GenerateBase64RefreshToken();
            // Find the user by email
            var user = _context.Database.GetCollection<User>("users").Find(user => user.Email == loginModel.Email).FirstOrDefault();
            // Check if the user exists
            if (user == null)
                return Unauthorized(new { message = "Utilisateur non trouvé" });
            // Verify the password
            var verifyPassword = BCrypt.Net.BCrypt.Verify(loginModel.Password, user.Password);
            if (verifyPassword == false)
                return Unauthorized(new { message = "Mot de passe incorrect" });

            if (user == null || user.Id == null)
            {
                return BadRequest(new { message = "L'utilisateur n'existe pas ou l'ID est nul" });
            }
            // Generate the access token
            var token = GenerateJwtToken(user.Id.ToString(), xsrfToken);

            var refreshTokenCollection = _context.Database.GetCollection<RefreshToken>("refreshtokens");
            var filter = Builders<RefreshToken>.Filter.Eq(rt => rt.UserId, user.Id);
            var update = Builders<RefreshToken>.Update
                .Set(rt => rt.Token, refreshToken)
                .SetOnInsert(rt => rt.CreatedAt, DateTime.UtcNow)
                .Set(rt => rt.UpdatedAt, DateTime.UtcNow)
                .Set(rt => rt.ExpiresAt, DateTime.UtcNow.AddDays(365));
            var options = new UpdateOptions { IsUpsert = true };
            // Upsert the refresh token in the database
            refreshTokenCollection.UpdateOne(filter, update, options);
            
            // Set the access token and the refresh token in the cookies
            Response.Cookies.Append("access_token", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                MaxAge = TimeSpan.FromHours(1),
                SameSite = SameSiteMode.Strict,
                Path = "/"
            });
            Response.Cookies.Append("refresh_token", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                MaxAge = TimeSpan.FromDays(365),
                Path = "/",
                SameSite = SameSiteMode.Strict
            });
            return Ok(new {
                accessTokenExpiresIn = TimeSpan.FromHours(1).TotalMilliseconds,
                refreshTokenExpiresIn = TimeSpan.FromDays(365).TotalMilliseconds,
                xsrfToken,
                user = new { user.Id, user.Username, user.Email, user.Lastname }
            });
        }
        catch (Exception ex)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new { message = ex.Message });
        }
    }

    // Logout method
    [HttpPost("logout")]
    public IActionResult Logout()
    {
        try
        {
            if (_context == null || _context.Database == null)
            {
            return BadRequest(new { message = "Échec de la connexion à la base de données" });
            }
            var refreshToken = Request.Cookies["refresh_token"];
            var refreshTokenCollection = _context.Database.GetCollection<RefreshToken>("refreshtokens");
            var getrefreshToken = refreshTokenCollection.Find(rt => rt.Token == refreshToken).FirstOrDefault();
            if (getrefreshToken != null)
            {
                refreshTokenCollection.DeleteOne(rt => rt.Token == refreshToken);
            }

            Response.Cookies.Delete("access_token");
            Response.Cookies.Delete("refresh_token");
            return Ok(new { message = "Déconnexion réussie" });
        }
        catch (Exception)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new { message = "Erreur lors de la déconnexion" });
        }
    }

    // Refresh token method
    [HttpPost("refresh-token")]
    public IActionResult Refresh()
    {
        try
        {
            if (_context == null || _context.Database == null)
            {
                return BadRequest(new { message = "Échec de la connexion à la base de données" });
            }
            // Check if the refresh token is not empty
            var refreshToken = Request.Cookies["refresh_token"];
            if (string.IsNullOrEmpty(refreshToken))
            {
                return BadRequest(new { message = "Le token de rafraîchissement est requis" });
            }

            var refreshTokenCollection = _context.Database.GetCollection<RefreshToken>("refreshtokens");
            // Find the refresh token by the token
            var validRefreshToken = refreshTokenCollection.Find(rt => rt.Token == refreshToken).FirstOrDefault();
            // Check if the refresh token is valid
            if (validRefreshToken == null)
            {
                return Unauthorized(new { message = "Token de rafraîchissement invalide" });
            }
            // Check if the refresh token is expired
            if (validRefreshToken.UserId == null || validRefreshToken.ExpiresAt < DateTime.UtcNow)
            {
                return Unauthorized(new { message = "Token de rafraîchissement invalide ou expiré" });
            }

            // Generate the XSRF token
            var xsrfToken = HashService.GenerateXsrfToken();
            // Generate the new refresh token
            var newRefreshToken = HashService.GenerateBase64RefreshToken();
            // Generate the access token
            var accessToken = GenerateJwtToken(validRefreshToken.UserId.ToString(), xsrfToken);

            var query = Builders<RefreshToken>.Filter.Eq(rt => rt.UserId, validRefreshToken.UserId);
            var update = Builders<RefreshToken>.Update
                .Set(rt => rt.Token, newRefreshToken)
                .Set(rt => rt.ExpiresAt, DateTime.UtcNow.AddDays(365));
            var options = new UpdateOptions { IsUpsert = true };
            // Upsert the refresh token in the database
            refreshTokenCollection.UpdateOne(query, update, options);

            // Set the access token and the refresh token in the cookies
            Response.Cookies.Append("access_token", accessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                MaxAge = TimeSpan.FromHours(1),
                SameSite = SameSiteMode.Strict,
                Path = "/"
            });
            Response.Cookies.Append("refresh_token", newRefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                MaxAge = TimeSpan.FromDays(365),
                Path = "/",
                SameSite = SameSiteMode.Strict
            });

            return Ok(new
            {
                accessTokenExpiresIn = TimeSpan.FromHours(1).TotalMilliseconds,
                refreshTokenExpiresIn = TimeSpan.FromDays(365).TotalMilliseconds,
                xsrfToken
            });
        }
        catch (Exception)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new { message = "Erreur interne du serveur lors du rafraîchissement du token" });
        }
    }
    
    private string GenerateJwtToken(string userId, string xsrfToken)
    {
        //Get the secret key from the configuration
        var secretKey = _configuration["JWT:SecretKey"] ?? throw new ArgumentNullException("SecretKey", "La configuration de SecretKey est manquante.");
        // Convert the secret key to a security key and create the credentials for the token
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        // Create the claims for the token
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId),
            new Claim("xsrfToken", xsrfToken)
        };
        // Create the token
        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:Issuer"],
            audience: _configuration["JWT:Audience"],
            claims: claims,
            expires: DateTime.Now.AddHours(1),
            signingCredentials: credentials);
        // Return the token
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

}



