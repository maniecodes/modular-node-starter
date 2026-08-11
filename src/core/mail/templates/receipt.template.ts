import { renderTemplate } from './template-engine';

interface ReceiptEmailData {
  appName: string;
  receiptNumber: string;
  amount: string;
  currency: string;
  issuedAt: string;
  year: number;
}

const template = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Payment receipt</title>
</head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:36px 0;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,.08);">
          <tr>
            <td style="background:#0f172a;padding:26px 36px;">
              <p style="margin:0;color:#fff;font-size:20px;font-weight:700;">{{appName}} Receipt</p>
            </td>
          </tr>
          <tr>
            <td style="padding:32px 36px;">
              <p style="margin:0 0 6px;color:#334155;">Receipt #: <strong>{{receiptNumber}}</strong></p>
              <p style="margin:0 0 6px;color:#334155;">Date: <strong>{{issuedAt}}</strong></p>
              <p style="margin:0 0 20px;color:#334155;">Amount: <strong>{{currency}} {{amount}}</strong></p>
              <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;"/>
              <p style="margin:0;color:#64748b;font-size:13px;">Thank you for your payment.</p>
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

export function renderReceiptEmail(input: Omit<ReceiptEmailData, 'year'>): string {
  return renderTemplate('receipt_email', template, {
    ...input,
    year: new Date().getFullYear(),
  });
}
