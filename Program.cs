using Microsoft.OpenApi.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;
using HarmonyStack_API_ASPNET_.Net.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);

// Add CORS configuration
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", builder =>
    {
        builder.WithOrigins("http://localhost:5173")
               .AllowAnyMethod()
               .AllowAnyHeader()
               .AllowCredentials();
    });
});

builder.Services.AddEndpointsApiExplorer();

// Add Swagger configuration
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "HarmonyStack API-ASPNET/.Net", Description = "Rest API HarmonyStack", Version = "v1" });
});

// Add services for MongoDB and controllers
builder.Services.AddControllers();
builder.Services.AddLogging();

// Add MongoContext and HashService
builder.Services.AddSingleton<MongoContext>();
builder.Services.AddSingleton<HashService>();

var app = builder.Build();
app.UseCors("AllowAll");

// Use Swagger only in development mode
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Todo API V1");
    });
}

// Use the Auth middleware
app.UseMiddleware<Auth>();

app.MapGet("/", () => "Hello World!");

// Map the controllers
app.MapControllers();

var _logger = app.Services.GetRequiredService<ILogger<Program>>();

// Try to connect to MongoDB
var mongoContext = app.Services.GetRequiredService<MongoContext>();

app.Run();
