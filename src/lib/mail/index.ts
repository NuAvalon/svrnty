// src/lib/mail/index.ts
import { Resend } from 'resend';
import { SVRNTY_DOMAIN } from '@/lib/config/domain';

const resend = new Resend(process.env.RESEND_API_KEY || process.env.RESEND);

const FROM_ADDRESS = process.env.EMAIL_FROM || 'verify@svrnty.is';

export async function sendVerificationEmail(to: string, code: string) {
  try {
    const { error } = await resend.emails.send({
      from: FROM_ADDRESS,
      to,
      subject: 'Verify your Soverentity Identity',
      text: `Your verification code is: ${code}\n\nThis code will expire in 15 minutes.`,
      html: `
        <div style="font-family: -apple-system, sans-serif; max-width: 480px; margin: 0 auto; padding: 2rem;">
          <h1 style="color: #1a1a2e; font-size: 1.5rem;">Verify your Soverentity Identity</h1>
          <div style="background: #f0f0f5; border-radius: 8px; padding: 1.5rem; text-align: center; margin: 1.5rem 0;">
            <code style="font-size: 2rem; letter-spacing: 0.3em; color: #1a1a2e; font-weight: bold;">${code}</code>
          </div>
          <p style="color: #666; font-size: 0.9rem;">This code expires in 15 minutes.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 1.5rem 0;" />
          <p style="color: #999; font-size: 0.8rem;">${SVRNTY_DOMAIN} — sovereign identity</p>
        </div>
      `
    });
    if (error) {
      console.error('Resend error:', error);
      return false;
    }
    return true;
  } catch (error) {
    console.error('Failed to send verification email:', error);
    return false;
  }
}
