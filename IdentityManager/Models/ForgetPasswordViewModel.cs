using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models
{
    public class ForgetPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
