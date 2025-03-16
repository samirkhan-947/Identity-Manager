
using System.Net.Mail;
using System.Net;
using System.Text;

namespace IdentityManager.Services
{
    public class EmailSevices : IMailSender
    {
        private readonly IConfiguration _configuration;
        public EmailSevices(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public async Task<bool> SendEmail(string emailTo, string subject, string body)
        {
            MailMessage mailMessage = new MailMessage
            {
                From = new MailAddress(_configuration.GetSection("MailSettings:SenderEmail").Value, _configuration.GetSection("MailSettings:SenderName").Value, Encoding.UTF8),
                Subject = subject,
                SubjectEncoding = Encoding.UTF8,
                Body = body,
                BodyEncoding = Encoding.UTF8,
                IsBodyHtml = true,
                Priority = MailPriority.High
            };
            mailMessage.To.Add(emailTo);

            using (SmtpClient smtpClient = new SmtpClient(_configuration.GetSection("MailSettings:Server").Value, Convert.ToInt32(_configuration.GetSection("MailSettings:Port").Value)))
            {
                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(_configuration.GetSection("MailSettings:SenderEmail").Value, _configuration.GetSection("MailSettings:Password").Value);
                smtpClient.DeliveryMethod = SmtpDeliveryMethod.Network;
                smtpClient.EnableSsl = true;

                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                try
                {
                    await smtpClient.SendMailAsync(mailMessage);
                    return true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                    return false;
                }
            }
        }
    }
}
