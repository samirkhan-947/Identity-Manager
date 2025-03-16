namespace IdentityManager.Services
{
    public interface IMailSender
    {
        Task<bool> SendEmail(string emailTo, string subject, string body);
    }
}
