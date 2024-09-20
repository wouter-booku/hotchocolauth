namespace AuthTest;

[Microsoft.AspNetCore.Authorization.Authorize]
[HotChocolate.Authorization.Authorize]
public sealed class MyQuery
{
    public string Hello => "Hello World!";
}