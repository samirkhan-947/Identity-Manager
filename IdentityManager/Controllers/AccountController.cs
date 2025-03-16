using IdentityManager.Models;
using IdentityManager.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;

namespace IdentityManager.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IMailSender _mailSender;
        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IMailSender mailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _mailSender = mailSender;
        }
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Register(string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            RegisterViewModel model = new RegisterViewModel();  
            return View(model);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel registerViewModel, string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser {UserName = registerViewModel.Email,Email=registerViewModel.Email,Name=registerViewModel.Name };
                var result = await _userManager.CreateAsync(user,registerViewModel.Password);
                if (result.Succeeded) 
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnurl);
                }
                AddErrors(result);
            }
            
            return View(registerViewModel);
        }


        [HttpGet]        
        public IActionResult Login(string returnurl =null)
        {
            ViewData["ReturnUrl"] = returnurl;
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model,string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
               var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe,lockoutOnFailure:true);
                if (result.Succeeded) 
                {
                    return LocalRedirect(returnurl);
                }
                if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(model);
                }
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOff()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
        [HttpGet]
        public IActionResult ForgetPassword()
        {
            
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgetPassword(ForgetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction("ForgetPasswordConfirmation");
                }
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callback = Url.Action("ResetPassword", "Account", new { userid = user.Id,code=code },protocol:HttpContext.Request.Scheme);
                await _mailSender.SendEmail(model.Email, "Reset Password - Identity Manager", "Please reset your password by clicking here: <a href=\"" + callback + "\">link</a>");
                return RedirectToAction("ForgetPasswordConfirmation");
            }
            
            return View(model);
        }
        [HttpGet]
        public IActionResult ForgetPasswordConfirmation()
        {
            return View();
        }
        [HttpGet]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ?View("Error"):View();
 
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction("ResetPasswordConfirmation");
                }
                var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
                if (result.Succeeded)
                {
                    return RedirectToAction("ForgetPasswordConfirmation");
                }
                AddErrors(result);
            }

            return View(model);
        }
        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}
