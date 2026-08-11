import { renderTemplate } from './template-engine';

interface OtpEmailData {
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
  <title>Your verification code</title>
</head>
<body style="margin:0;padding:0;background-color:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f5;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);">
          <tr>
            <td style="background:#18181b;padding:32px 40px;">
              <p style="margin:0;color:#ffffff;font-size:20px;font-weight:700;letter-spacing:-0.3px;">{{appName}}</p>
            </td>
          </tr>
          <tr>
            <td style="padding:40px 40px 32px;">
              <h1 style="margin:0 0 8px;font-size:24px;font-weight:700;color:#18181b;">Verify your identity</h1>
              <p style="margin:0 0 32px;font-size:15px;color:#71717a;line-height:1.6;">
                Use the code below to continue registration. It expires in
                <strong style="color:#18181b;">{{expiresInMinutes}} minutes</strong>.
              </p>

              <div style="background:#f4f4f5;border-radius:8px;padding:28px;text-align:center;margin-bottom:32px;">
                <p style="margin:0;font-size:42px;font-weight:800;letter-spacing:12px;color:#18181b;font-variant-numeric:tabular-nums;">
                  {{otp}}
                </p>
              </div>

              <p style="margin:0;font-size:13px;color:#a1a1aa;line-height:1.6;">
                If you did not request this code, you can ignore this email.
              </p>
            </td>
          </tr>
          <tr>
            <td style="border-top:1px solid #f4f4f5;padding:24px 40px;">
              <p style="margin:0;font-size:12px;color:#a1a1aa;">
                &copy; {{year}} {{appName}}
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

export function renderRegistrationOtpEmail(input: Omit<OtpEmailData, 'year'>): string {
  return renderTemplate('registration_otp_email', template, {
    ...input,
    year: new Date().getFullYear(),
  });
}
