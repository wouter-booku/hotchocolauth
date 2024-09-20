using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using HotChocolate.AspNetCore.Serialization;
using HotChocolate.Execution;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace AuthTest;

public class MultiSchemeTest
{
    private const string Audience = "test";
    private const string SchemeA = "A";
    private const string SchemeB = "B";
    private const string IssuerA = "https://a";
    private const string IssuerB = "https://b";
    private const string SigningKeyA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string SigningKeyB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    [Theory]
    [InlineData(IssuerA, SigningKeyA)]
    [InlineData(IssuerB, SigningKeyB)]
    public async Task Given_ValidJwt_When_ExecutingRequest_Then_RequestSuccessful(string issuer, string signingKey)
    {
        // Arrange
        var host = await CreateHostBuilder();
        var jwt = GenerateJwt(issuer, signingKey);
        using var client = host.GetTestServer().CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {jwt}");

        // Act
        var responseMessage = await client.PostAsync("/graphql", new StringContent("{\"query\":\"query { hello }\"}", Encoding.UTF8, "application/json"));
        var body = await responseMessage.Content.ReadAsStringAsync();
        
        // Assert
        responseMessage.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task Given_NoJwt_When_ExecutingRequest_Then_RequestUnauthorized()
    {
        // Arrange
        var host = await CreateHostBuilder();
        using var client = host.GetTestServer().CreateClient();

        // Act
        var responseMessage = await client.PostAsync("/graphql", new StringContent("{\"query\":\"query { hello }\"}", Encoding.UTF8, "application/json"));
        var body = await responseMessage.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, responseMessage.StatusCode);
    }
    
    private static string GenerateJwt(string issuer, string signingKeyString)
    {
        var claims = new Claim[] { new(JwtRegisteredClaimNames.Sub, "fake-jwt") };
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKeyString));

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddDays(1),
            signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256Signature));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
    private static async Task<IWebHost> CreateHostBuilder()
    {
        var host = new WebHostBuilder()
            .ConfigureServices(services =>
            {
                services.AddRouting();
                
                services.AddAuthentication(SchemeA) // Only the scheme added gets through the Authorize attribute.
                    .AddJwtBearer(SchemeA, o =>
                    {
                        o.TokenValidationParameters.ValidAudience = Audience;
                        o.TokenValidationParameters.ValidIssuer = IssuerA;
                        o.TokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SigningKeyA));
                    })
                    .AddJwtBearer(SchemeB, o =>
                    {
                        o.TokenValidationParameters.ValidAudience = Audience;
                        o.TokenValidationParameters.ValidIssuer = IssuerB;
                        o.TokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SigningKeyB));
                    });

                services.AddAuthorization(o =>
                {
                    // Tried this:
                    o.DefaultPolicy = new AuthorizationPolicyBuilder()
                        .AddAuthenticationSchemes(SchemeA, SchemeB)
                        .RequireAuthenticatedUser()
                        .Build();
                });
                
                services
                    .AddGraphQLServer()
                    .AddErrorFilter<MyErrorFilter>()
                    .AddAuthorization(o =>
                    {
                        // Tried this:
                        o.DefaultPolicy = new AuthorizationPolicyBuilder()
                            .AddAuthenticationSchemes(SchemeA, SchemeB)
                            .RequireAuthenticatedUser()
                            .Build();
                    })
                    .AddQueryType<MyQuery>();

                services.AddHttpResponseFormatter(_ => new MyHttpResponseFormatter());
            })
            .Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                app.UseAuthorization();
                app.UseEndpoints(routeBuilder => routeBuilder.MapGraphQL()/*.RequireAuthorization()*/); // If you add RequireAuthorization, all tests succeed, but it should also work with only the Authorize attribute.
            })
            .UseTestServer()
            .Build();

        await host.StartAsync();
        
        return host;
    }
}

public sealed class MyErrorFilter : IErrorFilter
{
    public IError OnError(IError error)
    {
        return error.Code is ErrorCodes.Authentication.NotAuthenticated or ErrorCodes.Authentication.NotAuthorized
            ? error.SetExtension("statusCode", (int)HttpStatusCode.Unauthorized)
            : error;
    }
}

public sealed class MyHttpResponseFormatter : DefaultHttpResponseFormatter
{
    protected override HttpStatusCode OnDetermineStatusCode(
        IQueryResult result,
        FormatInfo format,
        HttpStatusCode? proposedStatusCode)
    {
        if (result.Errors?.Count > 0)
        {
            var errorWithStatusCode = result.Errors.FirstOrDefault(error => error.Extensions?.ContainsKey("statusCode") ?? false);
            if (errorWithStatusCode is not null)
                return (HttpStatusCode)errorWithStatusCode.Extensions!["statusCode"]!; 
        }

        // In all other cases let Hot Chocolate figure out the appropriate status code.
        return base.OnDetermineStatusCode(result, format, proposedStatusCode);
    }
}
