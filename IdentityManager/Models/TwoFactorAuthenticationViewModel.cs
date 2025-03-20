namespace IdentityManager.Models
{
    public class TwoFactorAuthenticationViewModel
    {
        public string Code { get; set; }//used to login
        public string Token { get; set; } //used to register
        public string QRCodeUrl { get; set; }

    }
}
