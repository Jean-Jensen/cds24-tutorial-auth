using DataAccess.Entities;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Service;
using Service.Auth.Dto;

namespace Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    [HttpPost]
    [Route("login")]
    public async Task<LoginResponse> Login(
        [FromServices] SignInManager<User> signInManager,
        [FromServices] IValidator<LoginRequest> validator,
        [FromBody] LoginRequest data
    )
    {

        await validator.ValidateAndThrowAsync(data);
        
        var loginData = await signInManager.PasswordSignInAsync(data.Email, data.Password, false, true);
        if (!loginData.Succeeded)
        {
            throw new AuthenticationError();
        }
        
        /*
         if (validator.Validate(data).IsValid)
        {
            signInManager.PasswordSignInAsync(data.Email, data.Password, true, true);
            return new LoginResponse();
        }
        */

        return new LoginResponse();

    }

    [HttpPost]
    [Route("register")]
    public async Task<RegisterResponse> Register(
        IOptions<AppOptions> options,
        [FromServices] UserManager<User> userManager,
        [FromServices] IValidator<RegisterRequest> validator,
        [FromBody] RegisterRequest data
    )
    {
        
        
        /*if (!validator.Validate(data).IsValid)
        {
            throw new Exception();
        }*/
        await validator.ValidateAndThrowAsync(data);
        
        User u = new User { 
        UserName = data.Name,
        Email = data.Email};
        var result = await userManager.CreateAsync(u, data.Password);
        if (!result.Succeeded)
        {
            new ValidationError(
                result.Errors.ToDictionary(x => x.Code, x => new[] { x.Description })
                );
        }

        await userManager.AddToRoleAsync(u, "Reader");

        return new RegisterResponse(u.Email, u.UserName);
    }

    [HttpPost]
    [Route("logout")]
    public async Task<IResult> Logout([FromServices] SignInManager<User> signInManager)
    {
        await signInManager.SignOutAsync();
        return Results.Ok();
    }

    [HttpGet]
    [Route("userinfo")]
    public async Task<AuthUserInfo> UserInfo([FromServices] UserManager<User> userManager)
    {
        var username = (HttpContext.User.Identity?.Name) ?? throw new AuthenticationError();
        var user = await userManager.FindByNameAsync(username) ?? throw new AuthenticationError();
        var roles = await userManager.GetRolesAsync(user);
        var isAdmin = roles.Contains(Role.Admin);
        var canPublish = roles.Contains(Role.Editor) || isAdmin;
        return new AuthUserInfo(username, isAdmin, canPublish);
    }
}
