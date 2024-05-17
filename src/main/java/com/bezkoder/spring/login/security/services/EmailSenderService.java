package com.bezkoder.spring.login.security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class EmailSenderService {

    private static final Logger logger = LoggerFactory.getLogger(EmailSenderService.class);

    @Autowired
    private JavaMailSender mailSender;

    public String sendSimpleMail(String toEmail, String subject, String body) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(toEmail);
            message.setSubject(subject);
            message.setText(body);

            mailSender.send(message);
            logger.info("Email sent successfully to {}", toEmail);
            return "Email sent successfully to " + toEmail;
        } catch (Exception e) {
            logger.error("Error sending email to {}: {}", toEmail, e.getMessage());
            return "Error sending email to " + toEmail + ": " + e.getMessage();
        }
    }
}
