using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Linq;
using HarmonyStack_API_ASPNET_.Net.Services;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;
using HarmonyStack_API_ASPNET_.Net.Models;

[AttributeUsage(AttributeTargets.Method)]
public class UseAuthMiddlewareAttribute : Attribute
{
}

public class Auth
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _configuration;
    private readonly MongoContext _context;

    public Auth(RequestDelegate next, IConfiguration configuration, MongoContext context)
    {
        _next = next;
        _configuration = configuration;
        _context = context;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Get the endpoint from the context
        var endpoint = context.GetEndpoint();
        // Check if the endpoint has the UseAuthMiddleware attribute
        if (endpoint?.Metadata?.GetMetadata<UseAuthMiddlewareAttribute>() != null)
        {
            // Get the access token and the xsrf token from the cookies and the headers
            var accessToken = context.Request.Cookies["access_token"];
            var xsrfToken = context.Request.Headers["x-xsrf-token"].FirstOrDefault();
            // Check if the access token and the xsrf token are present
            if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(xsrfToken))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Token manquant ou xsrfToken manquant");
                return;
            }

            // Validate the token
            if (!ValidateToken(accessToken, xsrfToken, context))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Token invalide ou xsrfToken incorrect");
                return;
            }
            // Get the user from the context
            var user = context.Items["User"] as User;
            // Check if the user is present
            if(user == null)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Utilisateur non trouvé");
                return;
            }
            // Store the user id in the context
            context.Items["UserId"] = user.Id;
        }

        await _next(context);
    }

    private bool ValidateToken(string accessToken, string xsrfToken, HttpContext context)
    {
        if (_context == null || _context.Database == null)
        {
            return false;
        }
        
        // Create a new JwtSecurityTokenHandler and the validation parameters
        var tokenHandler = new JwtSecurityTokenHandler();
        // Create the validation parameters
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"] ?? throw new ArgumentNullException("JWT:SecretKey", "JWT Secret Key is not configured in the settings."))),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            // Validate the token
            var principal = tokenHandler.ValidateToken(accessToken, validationParameters, out var validatedToken);
            // Get the JwtSecurityToken from the validated token
            var jwtToken = (JwtSecurityToken)validatedToken;
            // Get the xsrf token from the token
            var tokenXsrf = jwtToken.Claims.First(claim => claim.Type == "xsrfToken").Value;

            // Check if the xsrf token is present
            if (tokenXsrf != xsrfToken)
            {
                return false;
            }

            // Add additional checks here, for example, check if the user exists in the database
            var userId = jwtToken.Claims.First(claim => claim.Type == JwtRegisteredClaimNames.Sub).Value;
            var user = _context.Database.GetCollection<User>("users").Find(u => u.Id == userId).FirstOrDefault();

            if (user == null)
            {
                return false;
            }

            context.Items["User"] = user; // Store the user in the context for future queries

            return true;
        }
        catch
        {
            return false;
        }
    }
}
