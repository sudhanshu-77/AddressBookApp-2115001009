using System;
using System.Threading.Tasks;
using MailKit.Net.Smtp;
using MimeKit;
using Microsoft.Extensions.Configuration;

namespace Middleware.Email
{
    public class SMTP
    {
        private readonly IConfiguration _config;

        public SMTP(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendEmailAsync(string to, string subject, string body)
        {
            try
            {
                // Create email message
                var email = new MimeMessage();


                email.From.Add(new MailboxAddress("AddressBook", _config["SMTP:Username"]));
                
                email.To.Add(new MailboxAddress("Recipient", to));
           
                email.Subject = subject;
                email.Body = new TextPart("html") { Text = body };  

                using var smtp = new SmtpClient();

                smtp.Connect("smtp.gmail.com", 587, MailKit.Security.SecureSocketOptions.StartTls);


                // Authenticate with the SMTP server
                await smtp.AuthenticateAsync(_config["SMTP:Username"], _config["SMTP:Password"]);

                // Send email
                await smtp.SendAsync(email);

                // Disconnect after sending
                await smtp.DisconnectAsync(true);

                // Log success
                Console.WriteLine($"[x] Email successfully sent to {to}");
            }
            catch (Exception ex)
            {
                // Log failure
                Console.WriteLine($"[!] Email sending failed: {ex.Message}");
            }
        }
    }
}
