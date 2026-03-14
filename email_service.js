/**
 * Email Service — Nodemailer + Gmail SMTP
 */
require('dotenv').config();
const nodemailer = require('nodemailer');

const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_PASS = process.env.GMAIL_PASS;

if (!GMAIL_USER || !GMAIL_PASS) {
  console.error('❌  Email service: GMAIL_USER or GMAIL_PASS is missing in .env');
} else {
  console.log(`✅  Email service: configured for ${GMAIL_USER}`);
}

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: GMAIL_USER, pass: GMAIL_PASS }
});

transporter.verify((error) => {
  if (error) {
    console.error('❌  Gmail SMTP connection failed:', error.message);
    console.error('    → Make sure GMAIL_PASS is a Gmail App Password, not your real password.');
    console.error('    → Get one at: https://myaccount.google.com/apppasswords');
  } else {
    console.log('✅  Gmail SMTP ready — emails will be sent from', GMAIL_USER);
  }
});

const FROM = () => `"${process.env.APP_NAME || 'RUN E-Voting System'}" <${GMAIL_USER}>`;

async function sendVerificationEmail(toEmail, token, fullName) {
  const verifyUrl = `${process.env.APP_URL || 'http://localhost:5000'}/api/auth/verify-email?token=${token}`;
  const info = await transporter.sendMail({
    from: FROM(), to: toEmail,
    subject: 'Verify Your Email - E-Voting System',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;border:1px solid #e0e0e0;border-radius:8px;">
        <h2 style="color:#2c3e50;">Hello, ${fullName}</h2>
        <p>Thank you for registering on the <strong>Secure E-Voting System</strong>.</p>
        <p>Please verify your school email address by clicking the button below:</p>
        <div style="text-align:center;margin:30px 0;">
          <a href="${verifyUrl}" style="background:#2c3e50;color:#fff;padding:14px 28px;border-radius:6px;text-decoration:none;font-size:16px;">Verify My Email</a>
        </div>
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break:break-all;color:#555;font-size:13px;">${verifyUrl}</p>
        <p style="color:#888;font-size:13px;">This link expires in <strong>24 hours</strong>.</p>
        <p style="color:#888;font-size:13px;">If you did not register, ignore this email.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
        <p style="color:#aaa;font-size:12px;text-align:center;">Secure E-Voting System | @run.edu.ng</p>
      </div>`
  });
  console.log(`✅  Verification email sent to ${toEmail} | MessageID: ${info.messageId}`);
}

async function sendVoterIdEmail(toEmail, fullName, voterId) {
  const info = await transporter.sendMail({
    from: FROM(), to: toEmail,
    subject: 'Your Voter ID - E-Voting System',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;border:1px solid #e0e0e0;border-radius:8px;">
        <h2 style="color:#2c3e50;">Your Voter ID is Ready!</h2>
        <p>Hello <strong>${fullName}</strong>,</p>
        <p>Your email has been verified. Here is your unique Voter ID:</p>
        <div style="text-align:center;margin:30px 0;">
          <span style="font-size:32px;font-weight:bold;letter-spacing:4px;color:#2c3e50;background:#f0f4f8;padding:16px 32px;border-radius:8px;display:inline-block;">${voterId}</span>
        </div>
        <p><strong>Keep this ID safe.</strong> You will need it to cast your vote.</p>
        <p style="color:#888;font-size:13px;">If you did not register for this system, please contact your administrator.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
        <p style="color:#aaa;font-size:12px;text-align:center;">Secure E-Voting System | @run.edu.ng</p>
      </div>`
  });
  console.log(`✅  Voter ID email sent to ${toEmail} | MessageID: ${info.messageId}`);
}

async function sendVoterIdRequestReceived(toEmail, fullName) {
  const info = await transporter.sendMail({
    from: FROM(), to: toEmail,
    subject: 'Voter ID Reset Request Received - E-Voting System',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;border:1px solid #e0e0e0;border-radius:8px;">
        <h2 style="color:#2c3e50;">Request Received</h2>
        <p>Hello <strong>${fullName}</strong>,</p>
        <p>We have received your request to reset your Voter ID. An administrator will review your request shortly.</p>
        <p>You will receive another email once your request has been processed.</p>
        <p style="color:#888;font-size:13px;">If you did not make this request, please contact your administrator immediately.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
        <p style="color:#aaa;font-size:12px;text-align:center;">Secure E-Voting System | @run.edu.ng</p>
      </div>`
  });
  console.log(`✅  Voter ID request confirmation sent to ${toEmail} | MessageID: ${info.messageId}`);
}

async function sendVoterIdResetApproved(toEmail, fullName, newVoterId) {
  const info = await transporter.sendMail({
    from: FROM(), to: toEmail,
    subject: 'Your New Voter ID - E-Voting System',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;border:1px solid #e0e0e0;border-radius:8px;">
        <h2 style="color:#2c3e50;">Voter ID Reset Approved</h2>
        <p>Hello <strong>${fullName}</strong>,</p>
        <p>Your Voter ID reset request has been approved. Here is your new Voter ID:</p>
        <div style="text-align:center;margin:30px 0;">
          <span style="font-size:32px;font-weight:bold;letter-spacing:4px;color:#2c3e50;background:#f0f4f8;padding:16px 32px;border-radius:8px;display:inline-block;">${newVoterId}</span>
        </div>
        <p><strong>Keep this ID safe.</strong> You will need it to cast your vote.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
        <p style="color:#aaa;font-size:12px;text-align:center;">Secure E-Voting System | @run.edu.ng</p>
      </div>`
  });
  console.log(`✅  Voter ID reset approval sent to ${toEmail} | MessageID: ${info.messageId}`);
}

async function sendVoterIdResetRejected(toEmail, fullName, adminNote) {
  const info = await transporter.sendMail({
    from: FROM(), to: toEmail,
    subject: 'Voter ID Reset Request Update - E-Voting System',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;border:1px solid #e0e0e0;border-radius:8px;">
        <h2 style="color:#9b1c1c;">Request Not Approved</h2>
        <p>Hello <strong>${fullName}</strong>,</p>
        <p>Your Voter ID reset request could not be approved at this time.</p>
        ${adminNote ? `<p><strong>Note from administrator:</strong> ${adminNote}</p>` : ''}
        <p>If you believe this is an error, please contact your election administrator.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
        <p style="color:#aaa;font-size:12px;text-align:center;">Secure E-Voting System | @run.edu.ng</p>
      </div>`
  });
  console.log(`✅  Voter ID reset rejection sent to ${toEmail} | MessageID: ${info.messageId}`);
}

async function sendPasswordResetEmail(toEmail, fullName, resetToken) {
  const resetUrl = `${process.env.APP_URL || 'http://localhost:5000'}/reset-password?token=${resetToken}`;
  const info = await transporter.sendMail({
    from: FROM(), to: toEmail,
    subject: 'Reset Your Password - E-Voting System',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;border:1px solid #e0e0e0;border-radius:8px;">
        <h2 style="color:#2c3e50;">Password Reset Request</h2>
        <p>Hello <strong>${fullName}</strong>,</p>
        <p>We received a request to reset your password for the <strong>Secure E-Voting System</strong>.</p>
        <p>Click the button below to set a new password:</p>
        <div style="text-align:center;margin:30px 0;">
          <a href="${resetUrl}" style="background:#9b1c1c;color:#fff;padding:14px 28px;border-radius:6px;text-decoration:none;font-size:16px;">Reset My Password</a>
        </div>
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break:break-all;color:#555;font-size:13px;">${resetUrl}</p>
        <p style="color:#888;font-size:13px;">This link expires in <strong>1 hour</strong>.</p>
        <p style="color:#888;font-size:13px;">If you did not request a password reset, you can safely ignore this email — your password will not change.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
        <p style="color:#aaa;font-size:12px;text-align:center;">Secure E-Voting System | @run.edu.ng</p>
      </div>`
  });
  console.log(`✅  Password reset email sent to ${toEmail} | MessageID: ${info.messageId}`);
}

module.exports = {
  sendVerificationEmail,
  sendVoterIdEmail,
  sendVoterIdRequestReceived,
  sendVoterIdResetApproved,
  sendVoterIdResetRejected,
  sendPasswordResetEmail
};
