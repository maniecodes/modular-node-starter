import { renderTemplate } from './template-engine';

interface WelcomeEmailData {
  appName: string;
  userName: string;
  year: number;
}

const template = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Welcome</title>
</head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:36px 0;">
    <tr>
      <td align="center">
        <table width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,.08);">
          <tr>
            <td style="background:#1d4ed8;padding:28px 36px;">
              <p style="margin:0;color:#fff;font-size:20px;font-weight:700;">{{appName}}</p>
            </td>
          </tr>
          <tr>
            <td style="padding:36px;">
              <h1 style="margin:0 0 10px;font-size:26px;color:#0f172a;">Welcome, {{userName}}!</h1>
              <p style="margin:0;color:#475569;line-height:1.6;">
                Your account is ready. We're excited to have you on board.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding:20px 36px;border-top:1px solid #e2e8f0;">
              <p style="margin:0;color:#94a3b8;font-size:12px;">&copy; {{year}} {{appName}}</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

export function renderWelcomeEmail(input: Omit<WelcomeEmailData, 'year'>): string {
  return renderTemplate('welcome_email', template, {
    ...input,
    year: new Date().getFullYear(),
  });
}
