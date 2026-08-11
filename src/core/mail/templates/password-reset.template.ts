import { renderTemplate } from './template-engine';

interface PasswordResetEmailData {
  otp: string;
  expiresInMinutes: number;
  appName: string;
  year: number;
}

const template = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Password reset code</title>
</head>
<body style="margin:0;padding:0;background-color:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f5;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,.08);">
          <tr>
            <td style="background:#7f1d1d;padding:32px 40px;">
              <p style="margin:0;color:#ffffff;font-size:20px;font-weight:700;">{{appName}}</p>
            </td>
          </tr>
          <tr>
            <td style="padding:40px;">
              <h1 style="margin:0 0 10px;font-size:24px;color:#111827;">Reset your password</h1>
              <p style="margin:0 0 28px;color:#6b7280;line-height:1.6;">
                We received a request to reset your password. Use the OTP below.
                It expires in <strong>{{expiresInMinutes}} minutes</strong>.
              </p>
              <div style="padding:24px;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;text-align:center;margin-bottom:28px;">
                <p style="margin:0;font-size:40px;letter-spacing:10px;color:#7f1d1d;font-weight:800;">{{otp}}</p>
              </div>
              <p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.5;">
                If you did not request this, ignore this email and consider changing your password if you suspect account compromise.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding:20px 40px;border-top:1px solid #e5e7eb;">
              <p style="margin:0;color:#9ca3af;font-size:12px;">&copy; {{year}} {{appName}}</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

export function renderPasswordResetEmail(input: Omit<PasswordResetEmailData, 'year'>): string {
  return renderTemplate('password_reset_email', template, {
    ...input,
    year: new Date().getFullYear(),
  });
}
