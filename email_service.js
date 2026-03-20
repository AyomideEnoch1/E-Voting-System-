/**
 * Email Service — Gmail SMTP via Nodemailer
 * Handles verification emails and voter ID delivery
 */
require('dotenv').config();
const nodemailer = require('nodemailer');

// ── Validate env vars on startup ──
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_PASS = process.env.GMAIL_APP_PASSWORD;
const APP_NAME   = process.env.APP_NAME || 'RUN E-Voting System';

if (!GMAIL_USER || !GMAIL_PASS) {
  console.error('❌  Email service: GMAIL_USER or GMAIL_APP_PASSWORD is missing in .env');
} else {
  console.log(`✅  Email service: Gmail SMTP configured — sending from ${GMAIL_USER}`);
}

// ── Transporter ──
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: GMAIL_USER,
    pass: GMAIL_PASS,   // Use a Gmail App Password, NOT your account password
  },
});

// ── Helper ──
async function sendMail({ to, subject, html }) {
  const info = await transporter.sendMail({
    from: `"${APP_NAME}" <${GMAIL_USER}>`,
    to,
    subject,
    html,
  });
  return info;
}

/**
 * Send email verification link
 */
async function sendVerificationEmail(toEmail, token, fullName) {
  const verifyUrl = `${process.env.APP_URL || 'http://localhost:5000'}/api/auth/verify-email?token=${token}`;
  try {
    const info = await sendMail({
      to: toEmail,
      subject: 'Verify Your Email - E-Voting System',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;border:1px solid #e0e0e0;border-radius:8px;">
          <h2 style="color:#2c3e50;">Hello, ${fullName}</h2>
          <p>Thank you for registering on the <strong>Secure E-Voting System</strong>.</p>
          <p>Please verify your school email address by clicking the button below:</p>
          <div style="text-align:center;margin:30px 0;">
            <a href="${verifyUrl}"
               style="background:#2c3e50;color:#fff;padding:14px 28px;border-radius:6px;text-decoration:none;font-size:16px;">
              Verify My Email
            </a>
          </div>
          <p>Or copy and paste this link into your browser:</p>
          <p style="word-break:break-all;color:#555;font-size:13px;">${verifyUrl}</p>
          <p style="color:#888;font-size:13px;">This link expires in <strong>24 hours</strong>.</p>
          <p style="color:#888;font-size:13px;">If you did not register, ignore this email.</p>
          <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
          <p style="color:#aaa;font-size:12px;text-align:center;">Secure E-Voting System | @run.edu.ng</p>
        </div>
      `
    });
    console.log(`✅  Verification email sent to ${toEmail} | MessageID: ${info.messageId}`);
  } catch (err) {
    console.error(`❌  Failed to send verification email to ${toEmail}:`, err.message);
    throw err;
  }
}

/**
 * Send generated Voter ID to verified user
 */
async function sendVoterIdEmail(toEmail, fullName, voterId) {
  try {
    const info = await sendMail({
      to: toEmail,
      subject: 'Your Voter ID - E-Voting System',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;border:1px solid #e0e0e0;border-radius:8px;">
          <h2 style="color:#2c3e50;">Your Voter ID is Ready!</h2>
          <p>Hello <strong>${fullName}</strong>,</p>
          <p>Your email has been verified. Here is your unique Voter ID:</p>
          <div style="text-align:center;margin:30px 0;">
            <span style="font-size:32px;font-weight:bold;letter-spacing:4px;color:#2c3e50;background:#f0f4f8;padding:16px 32px;border-radius:8px;display:inline-block;">
              ${voterId}
            </span>
          </div>
          <p><strong>Keep this ID safe.</strong> You will need it to cast your vote.</p>
          <p style="color:#888;font-size:13px;">If you did not register for this system, please contact your administrator.</p>
          <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
          <p style="color:#aaa;font-size:12px;text-align:center;">Secure E-Voting System | @run.edu.ng</p>
        </div>
      `
    });
    console.log(`✅  Voter ID email sent to ${toEmail} | MessageID: ${info.messageId}`);
  } catch (err) {
    console.error(`❌  Failed to send Voter ID email to ${toEmail}:`, err.message);
    throw err;
  }
}

/**
 * Send election notification to a voter
 * Called in bulk by the admin notify-voters route
 */
async function sendElectionNotice(toEmail, fullName, { electionTitle, startTime, endTime, customMessage }) {
  const appName = process.env.APP_NAME || 'RUN E-Voting System';
  const appUrl  = process.env.APP_URL  || 'http://localhost:5000';

  const fmt = (dt) => new Date(dt).toLocaleString('en-NG', {
    dateStyle: 'full', timeStyle: 'short', timeZone: 'Africa/Lagos'
  });

  try {
    const info = await sendMail({
      to: toEmail,
      subject: `📢 Upcoming Election: ${electionTitle}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;border:1px solid #e0e0e0;border-radius:8px;">
          <h2 style="color:#2c3e50;">Hello, ${fullName} 👋</h2>
          <p>You are receiving this message because you are a registered voter on the <strong>${appName}</strong>.</p>

          ${customMessage ? `
          <div style="background:#f0f4f8;border-left:4px solid #2c3e50;padding:14px 18px;border-radius:4px;margin:20px 0;">
            <p style="margin:0;color:#2c3e50;font-size:15px;">${customMessage}</p>
          </div>` : ''}

          <h3 style="color:#2c3e50;margin-top:28px;">📋 Election Details</h3>
          <table style="width:100%;border-collapse:collapse;font-size:14px;">
            <tr style="background:#f8f9fa;">
              <td style="padding:10px 14px;font-weight:bold;width:35%;border:1px solid #e0e0e0;">Election</td>
              <td style="padding:10px 14px;border:1px solid #e0e0e0;">${electionTitle}</td>
            </tr>
            <tr>
              <td style="padding:10px 14px;font-weight:bold;border:1px solid #e0e0e0;">Voting Opens</td>
              <td style="padding:10px 14px;border:1px solid #e0e0e0;">${fmt(startTime)}</td>
            </tr>
            <tr style="background:#f8f9fa;">
              <td style="padding:10px 14px;font-weight:bold;border:1px solid #e0e0e0;">Voting Closes</td>
              <td style="padding:10px 14px;border:1px solid #e0e0e0;">${fmt(endTime)}</td>
            </tr>
          </table>

          <div style="background:#fff8e1;border:1px solid #ffe082;border-radius:6px;padding:14px 18px;margin:24px 0;">
            <p style="margin:0;font-size:14px;color:#7a6a00;">
              ⚠️ <strong>Reminder:</strong> Have your <strong>Voter ID</strong> ready before you log in to vote.
            </p>
          </div>

          <div style="text-align:center;margin:30px 0;">
            <a href="${appUrl}"
               style="background:#2c3e50;color:#fff;padding:14px 28px;border-radius:6px;text-decoration:none;font-size:16px;">
              Go to Voting Portal
            </a>
          </div>

          <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
          <p style="color:#aaa;font-size:12px;text-align:center;">${appName} | @run.edu.ng</p>
        </div>
      `
    });
    console.log(`✅  Election notice sent to ${toEmail} | MessageID: ${info.messageId}`);
  } catch (err) {
    console.error(`❌  Failed to send election notice to ${toEmail}:`, err.message);
    throw err;
  }
}

/**
 * Send password reset link (expires 1 hour)
 */
async function sendPasswordResetEmail(toEmail, fullName, token) {
  const appName  = process.env.APP_NAME || 'RUN E-Voting System';
  const resetUrl = `${process.env.APP_URL || 'http://localhost:5000'}/reset-password?token=${token}`;
  try {
    const info = await sendMail({
      to: toEmail,
      subject: '🔐 Password Reset Request — SecureVote',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;border:1px solid #e0e0e0;border-radius:8px;">
          <h2 style="color:#2c3e50;">Password Reset</h2>
          <p>Hello <strong>${fullName}</strong>,</p>
          <p>We received a request to reset your password. Click the button below to set a new one:</p>
          <div style="text-align:center;margin:30px 0;">
            <a href="${resetUrl}" style="background:#9b1c1c;color:#fff;padding:14px 28px;border-radius:6px;text-decoration:none;font-size:16px;">
              Reset My Password
            </a>
          </div>
          <p>Or copy and paste this link into your browser:</p>
          <p style="word-break:break-all;color:#555;font-size:13px;">${resetUrl}</p>
          <p style="color:#888;font-size:13px;">This link expires in <strong>1 hour</strong>. If you did not request a password reset, you can safely ignore this email.</p>
          <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
          <p style="color:#aaa;font-size:12px;text-align:center;">${appName} | @run.edu.ng</p>
        </div>
      `
    });
    console.log(`✅  Password reset email sent to ${toEmail} | MessageID: ${info.messageId}`);
  } catch (err) {
    console.error(`❌  Failed to send password reset email to ${toEmail}:`, err.message);
    throw err;
  }
}

/**
 * Confirm voter's Voter ID reset request was received (pending admin review)
 */
async function sendVoterIdRequestReceived(toEmail, fullName) {
  const appName = process.env.APP_NAME || 'RUN E-Voting System';
  try {
    await sendMail({
      to: toEmail,
      subject: '📋 Voter ID Reset Request Received — SecureVote',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;border:1px solid #e0e0e0;border-radius:8px;">
          <h2 style="color:#2c3e50;">Request Received</h2>
          <p>Hello <strong>${fullName}</strong>,</p>
          <p>Your <strong>Voter ID reset request</strong> has been received and is currently under review by an administrator.</p>
          <div style="background:#fff8e1;border:1px solid #ffe082;border-radius:6px;padding:14px 18px;margin:20px 0;">
            <p style="margin:0;font-size:14px;color:#7a6a00;">⚠️ Your current Voter ID remains valid until an administrator approves this request.</p>
          </div>
          <p>You will receive another email once a decision has been made.</p>
          <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
          <p style="color:#aaa;font-size:12px;text-align:center;">${appName} | @run.edu.ng</p>
        </div>
      `
    });
    console.log(`✅  Voter ID request confirmation sent to ${toEmail}`);
  } catch (err) {
    console.error(`❌  Failed to send voter ID request confirmation to ${toEmail}:`, err.message);
    throw err;
  }
}

/**
 * Send new Voter ID after admin approves reset
 */
async function sendVoterIdResetApproved(toEmail, fullName, newVoterId) {
  const appName = process.env.APP_NAME || 'RUN E-Voting System';
  try {
    await sendMail({
      to: toEmail,
      subject: '✅ Your New Voter ID — SecureVote',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;border:1px solid #e0e0e0;border-radius:8px;">
          <h2 style="color:#1a6b3a;">Voter ID Reset Approved</h2>
          <p>Hello <strong>${fullName}</strong>,</p>
          <p>Your Voter ID reset request has been <strong>approved</strong>. Here is your new Voter ID:</p>
          <div style="text-align:center;margin:30px 0;">
            <span style="font-size:32px;font-weight:bold;letter-spacing:4px;color:#2c3e50;background:#f0f4f8;padding:16px 32px;border-radius:8px;display:inline-block;">
              ${newVoterId}
            </span>
          </div>
          <p><strong>Keep this ID safe.</strong> Your previous Voter ID is no longer valid.</p>
          <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
          <p style="color:#aaa;font-size:12px;text-align:center;">${appName} | @run.edu.ng</p>
        </div>
      `
    });
    console.log(`✅  Voter ID approval email sent to ${toEmail}`);
  } catch (err) {
    console.error(`❌  Failed to send voter ID approval email to ${toEmail}:`, err.message);
    throw err;
  }
}

/**
 * Notify voter their Voter ID reset was rejected
 */
async function sendVoterIdResetRejected(toEmail, fullName, reason) {
  const appName = process.env.APP_NAME || 'RUN E-Voting System';
  try {
    await sendMail({
      to: toEmail,
      subject: '❌ Voter ID Reset Request Declined — SecureVote',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;border:1px solid #e0e0e0;border-radius:8px;">
          <h2 style="color:#9b1c1c;">Request Declined</h2>
          <p>Hello <strong>${fullName}</strong>,</p>
          <p>Unfortunately, your Voter ID reset request has been <strong>declined</strong>.</p>
          ${reason ? `
          <div style="background:#fff0f0;border:1px solid #ffcccc;border-radius:6px;padding:14px 18px;margin:20px 0;">
            <p style="margin:0;font-size:14px;color:#9b1c1c;"><strong>Reason:</strong> ${reason}</p>
          </div>` : ''}
          <p>Your current Voter ID remains valid. If you believe this is an error, please contact the system administrator.</p>
          <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
          <p style="color:#aaa;font-size:12px;text-align:center;">${appName} | @run.edu.ng</p>
        </div>
      `
    });
    console.log(`✅  Voter ID rejection email sent to ${toEmail}`);
  } catch (err) {
    console.error(`❌  Failed to send voter ID rejection email to ${toEmail}:`, err.message);
    throw err;
  }
}

module.exports = {
  sendVerificationEmail,
  sendVoterIdEmail,
  sendElectionNotice,
  sendPasswordResetEmail,
  sendVoterIdRequestReceived,
  sendVoterIdResetApproved,
  sendVoterIdResetRejected
};
