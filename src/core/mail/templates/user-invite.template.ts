export function userInviteTemplate(input: {
  appName: string;
  inviteeEmail: string;
  invitedBy: string;
  acceptUrl: string;
  expiresAt: Date;
}): string {
  const expiryText = input.expiresAt.toUTCString();

  return `
    <div style="font-family:Arial,sans-serif;line-height:1.5;color:#111;max-width:640px;margin:0 auto;">
      <h2 style="margin-bottom:12px;">You are invited to join ${input.appName}</h2>
      <p>Hello,</p>
      <p>
        ${input.invitedBy} invited <strong>${input.inviteeEmail}</strong> to join the staff workspace.
      </p>
      <p>
        Click the button below to accept your invite and create your account:
      </p>
      <p style="margin:24px 0;">
        <a href="${input.acceptUrl}" style="background:#111;color:#fff;padding:12px 20px;text-decoration:none;border-radius:6px;display:inline-block;">
          Accept Invite
        </a>
      </p>
      <p>This invite expires on <strong>${expiryText}</strong>.</p>
      <p>If you did not expect this invite, you can ignore this message.</p>
    </div>
  `;
}
