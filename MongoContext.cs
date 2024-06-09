using MongoDB.Driver;
// using Microsoft.Extensions.Logging;
using MongoDB.Bson;

public class MongoContext
{
    public IMongoDatabase? Database { get; }
    private readonly ILogger<MongoContext> _logger;

    public MongoContext(IConfiguration configuration, ILogger<MongoContext> logger)
    {
        _logger = logger;
        // Get the connection string and the database name from the configuration
        var connectionString = configuration.GetSection("MongoDB:ConnectionString").Value;
        var databaseName = configuration.GetSection("MongoDB:DatabaseName").Value;

        try
        {
            // Create a new MongoClient and get the database
            var client = new MongoClient(connectionString);
            Database = client.GetDatabase(databaseName);
            if(Database != null)
            {
                _logger.LogInformation("Connected to MongoDB at MongoContext");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to connect to MongoDB");
            throw;
        }
    }
}