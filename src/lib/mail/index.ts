// src/lib/mail/index.ts
import nodemailer from 'nodemailer';

console.log('Email configuration:', {
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER // don't log the password
    }
  });

// In production, you'd want to use a real email service
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',  // Or your preferred SMTP server
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

export async function sendVerificationEmail(to: string, code: string) {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to,
      subject: 'Verify your Soverentity Identity',
      text: `Your verification code is: ${code}`,
      html: `
        <h1>Verify your Soverentity Identity</h1>
        <p>Your verification code is: <strong>${code}</strong></p>
        <p>This code will expire in 15 minutes.</p>
      `
    });
    return true;
  } catch (error) {
    console.error('Failed to send verification email:', error);
    return false;
  }
}