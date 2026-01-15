var builder = WebApplication.CreateBuilder(args);

// Controllers (si tu utilises des controllers)
builder.Services.AddControllers();

// Swagger / OpenAPI (net8)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapControllers();

// Optionnel: endpoint simple pour tester vite
app.MapGet("/", () => "AiTrace.Api is running (net8)");

app.Run();
