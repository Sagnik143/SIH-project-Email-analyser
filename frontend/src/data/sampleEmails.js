/**
 * Sample Emails for Demo
 * Realistic sample emails covering various threat categories.
 */

export const SAMPLE_EMAILS = [
  {
    id: 'sample-1',
    name: '🟢 Legitimate Business Email',
    category: 'legitimate',
    raw: `Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
        by mx.google.com with SMTPS id a1234567890;
        Mon, 15 Jan 2024 09:30:22 -0800 (PST)
Received: from [10.0.0.5] by smtp.gmail.com with ESMTPSA id b9876543210
        for <employee@company.com>;
        Mon, 15 Jan 2024 09:30:20 -0800 (PST)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@company.com header.s=google header.b=abc123;
       spf=pass (google.com: domain of john.smith@company.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=john.smith@company.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=company.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=company.com; s=google; h=from:to:subject:date:message-id; bh=abc123def456; b=xyz789
From: John Smith <john.smith@company.com>
To: Jane Doe <jane.doe@company.com>
Subject: Q4 Project Update - Marketing Team
Date: Mon, 15 Jan 2024 09:30:18 -0800
Message-ID: <CAExample123@mail.gmail.com>
Return-Path: <john.smith@company.com>
Content-Type: text/plain; charset="UTF-8"

Hi Jane,

I wanted to share the Q4 project update with you. The marketing team has completed the following milestones:

1. Social media campaign launch - completed on schedule
2. Website redesign phase 2 - 90% complete
3. Customer survey analysis - final report attached

Could we schedule a call this week to discuss the findings? I'm available Tuesday or Thursday afternoon.

Best regards,
John Smith
Marketing Director
Company Inc.
Phone: (555) 123-4567`
  },
  {
    id: 'sample-2',
    name: '🔴 PayPal Phishing Attack',
    category: 'phishing',
    raw: `Received: from unknown (HELO mail.secure-paypal-verify.xyz) (185.234.72.19)
          by 0 with SMTP; Mon, 15 Jan 2024 14:22:33 +0000
Received: from localhost (unknown [10.0.0.1])
	by mail.secure-paypal-verify.xyz (Postfix) with ESMTP id ABC123
	for <victim@gmail.com>; Mon, 15 Jan 2024 14:22:30 +0000
Received: from [91.234.56.78] by relay1.offshore-host.top with SMTP
          id DEF456; Mon, 15 Jan 2024 14:22:28 +0000
From: PayPal Security Team <security@secure-paypal-verify.xyz>
To: victim@gmail.com
Subject: ⚠️ URGENT: Your PayPal Account Has Been Limited - Verify Now
Date: Mon, 15 Jan 2024 14:22:25 +0000
Message-ID: <random123@secure-paypal-verify.xyz>
Return-Path: <bounce@secure-paypal-verify.xyz>
Reply-To: paypal-support@gmail.com
Authentication-Results: mx.google.com;
       dkim=fail reason="signature missing";
       spf=fail (google.com: domain of secure-paypal-verify.xyz does not designate 185.234.72.19 as permitted sender) smtp.mailfrom=bounce@secure-paypal-verify.xyz;
       dmarc=fail (p=REJECT sp=REJECT) header.from=paypal.com
Received-SPF: fail (domain of secure-paypal-verify.xyz does not designate 91.234.56.78 as permitted sender) client-ip=91.234.56.78;
Content-Type: text/html; charset="UTF-8"

Dear Valued PayPal Customer,

We have detected unusual activity on your PayPal account. Your account has been temporarily LIMITED due to suspicious login attempts from an unauthorized location.

IMMEDIATE ACTION REQUIRED: You must verify your identity within 24 hours or your account will be permanently suspended.

Click here to verify your account: http://paypal-login.secure-verify.xyz/auth/confirm?id=victim@gmail.com

What happened:
- Unauthorized access detected from IP: 192.168.1.1 (Moscow, Russia)
- Multiple failed login attempts
- Suspicious transaction flagged: $2,499.99

If you do not verify your identity immediately, we will be forced to:
1. Permanently suspend your account
2. Freeze all pending transactions
3. Report to relevant authorities

This is your FINAL WARNING. Act now to secure your account.

Verify Now: http://bit.ly/paypal-verify-secure

PayPal Security Team
© 2024 PayPal, Inc. All rights reserved.
This is an automated security notification. Do not reply to this email.`
  },
  {
    id: 'sample-3',
    name: '🟣 CEO Impersonation / BEC',
    category: 'impersonation',
    raw: `Received: from mail-out.protonmail.ch (mail-out.protonmail.ch [185.70.40.10])
        by mx.company.com with ESMTPS id A1B2C3D4
        for <finance@company.com>;
        Tue, 16 Jan 2024 08:15:33 -0500
Received: from [10.2.3.4] by mail.protonmail.ch with ESMTPSA
        for <finance@company.com>;
        Tue, 16 Jan 2024 13:15:30 +0000
From: CEO Robert Wilson <ceo.robert.wilson@protonmail.com>
To: Sarah Johnson <finance@company.com>
Subject: Urgent Wire Transfer - Confidential
Date: Tue, 16 Jan 2024 13:15:28 +0000
Message-ID: <msg-xyz789@protonmail.com>
Return-Path: <ceo.robert.wilson@protonmail.com>
Reply-To: ceo.robert.wilson.private@gmail.com
Authentication-Results: mx.company.com;
       dkim=pass header.d=protonmail.com header.s=proton;
       spf=pass (mx.company.com: domain of ceo.robert.wilson@protonmail.com designates 185.70.40.10 as permitted sender) smtp.mailfrom=ceo.robert.wilson@protonmail.com;
       dmarc=fail (p=REJECT) header.from=company.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=protonmail.com; s=proton; h=from:to:subject:date:message-id; bh=abc123def456; b=xyz789proton
Received-SPF: pass (protonmail.com: domain designates 185.70.40.10 as permitted sender) client-ip=185.70.40.10;
Content-Type: text/plain; charset="UTF-8"

Sarah,

I need you to process an urgent wire transfer today. I'm currently in a board meeting and cannot talk on the phone. Please handle this immediately and keep it confidential between us only.

Transfer Details:
Amount: $47,500.00
Beneficiary: Global Solutions Ltd
Account Number: 8847201234
Bank: First International Bank
Routing Number: 0291837465
Reference: Invoice #INV-2024-0892

This is for a confidential acquisition deal we're closing. Do not discuss this with anyone else in the office. I will explain everything when I'm back tomorrow.

Please confirm once the transfer is completed by replying to my personal email.

Thanks,
Robert Wilson
CEO, Company Inc.

Sent from my iPhone`
  },
  {
    id: 'sample-4',
    name: '🔴 Microsoft Credential Harvesting',
    category: 'phishing',
    raw: `Received: from unknown (HELO smtp.microsft-365-security.online) (103.45.67.89)
          by 0 with SMTP; Wed, 17 Jan 2024 03:44:12 +0000
Received: from vps-node3.hostinger.com (unknown [103.45.67.89])
	by smtp.microsft-365-security.online (Postfix) with ESMTP
	for <admin@university.edu>; Wed, 17 Jan 2024 03:44:10 +0000
From: "Microsoft 365 Security" <no-reply@microsft-365-security.online>
To: admin@university.edu
Subject: [Action Required] Your Microsoft 365 Password Expires in 24 Hours
Date: Wed, 17 Jan 2024 03:44:08 +0000
Message-ID: <auto-gen-987654@microsft-365-security.online>
Return-Path: <no-reply@microsft-365-security.online>
Authentication-Results: mx.university.edu;
       dkim=fail reason="unaligned signing domain";
       spf=softfail (transitioning domain of microsft-365-security.online) smtp.mailfrom=no-reply@microsft-365-security.online;
       dmarc=fail (p=REJECT) header.from=microsoft.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=microsft-365-security.online; s=selector1; h=from:to:subject; b=fake123
Received-SPF: softfail (microsft-365-security.online: transitioning domain)
Content-Type: text/html; charset="UTF-8"

Microsoft 365 Security Center

Dear admin@university.edu,

Your Microsoft 365 password is set to expire in 24 hours. To prevent any disruption to your email and Teams services, you must update your password immediately.

⚠️ If your password expires, you will lose access to:
- Outlook Email
- Microsoft Teams
- OneDrive Files
- SharePoint Documents

Click below to keep your current password:
https://microsft-365-security.online/auth/login?user=admin@university.edu&session=abc123

Keep Same Password →

This is a mandatory security update as per your organization's compliance requirements. Failure to update will result in account deactivation.

If you did not request this change, please click here to report unauthorized access:
https://microsft-365-security.online/report

Microsoft Corporation
One Microsoft Way, Redmond, WA 98052
Privacy Statement | Terms of Use`
  },
  {
    id: 'sample-5',
    name: '🟠 Fake Invoice / Malware',
    category: 'fraud',
    raw: `Received: from mail.invoice-services.top (unknown [45.77.123.45])
        by mx.target-company.com with ESMTP id XYZ789
        for <accounts@target-company.com>;
        Thu, 18 Jan 2024 10:05:44 -0600
Received: from localhost (localhost [127.0.0.1])
	by mail.invoice-services.top (Postfix) with ESMTP
	for <accounts@target-company.com>; Thu, 18 Jan 2024 16:05:40 +0000
From: "Accounts Department" <billing@invoice-services.top>
To: accounts@target-company.com
Subject: Invoice #INV-2024-8834 - Payment Overdue - FINAL NOTICE
Date: Thu, 18 Jan 2024 16:05:38 +0000
Message-ID: <inv-notice-8834@invoice-services.top>
Return-Path: <billing@invoice-services.top>
Reply-To: payments@invoice-services.top
Authentication-Results: mx.target-company.com;
       dkim=fail reason="signature missing";
       spf=fail (domain of invoice-services.top does not designate 45.77.123.45 as permitted sender);
       dmarc=fail (p=QUARANTINE)
Received-SPF: fail (domain of invoice-services.top does not designate 45.77.123.45 as permitted sender) client-ip=45.77.123.45;
Content-Type: multipart/mixed; boundary="boundary123"

ATTENTION: OVERDUE PAYMENT NOTICE

Dear Accounts Payable,

This is a FINAL NOTICE regarding your overdue invoice #INV-2024-8834 for services rendered in December 2023.

Invoice Details:
- Invoice Number: INV-2024-8834
- Amount Due: $12,750.00
- Original Due Date: January 5, 2024
- Days Overdue: 13 days

A penalty fee of $637.50 (5%) has been applied to your account. If payment is not received within 48 hours, we will be forced to escalate this matter to our collection agency and legal action will be taken.

Please find the attached invoice document for your records:
📎 Invoice_INV-2024-8834.pdf.exe (248 KB)

To process payment immediately, please use the following updated bank details:
Bank: Offshore International Bank
Account Name: Global Invoice Services LLC
Account: 9928374651
SWIFT: OIBKUS33

Pay the attached invoice immediately to avoid further penalties.

Regards,
Collections Department
Invoice Services International
Phone: +1 (800) 555-0199`
  },
  {
    id: 'sample-6',
    name: '🟠 Nigerian Advance Fee Fraud',
    category: 'fraud',
    raw: `Received: from webmail.ng-ministry.org (unknown [41.58.220.100])
        by mx.victim-mail.com with SMTP
        for <recipient@victim-mail.com>;
        Fri, 19 Jan 2024 07:33:21 +0100
Received: from [41.58.220.100] by webmail.ng-ministry.org with HTTP;
        Fri, 19 Jan 2024 07:33:18 +0100
From: "Barrister Ahmed Mohammed" <ahmed.mohammed@ng-ministry.org>
To: undisclosed-recipients
Subject: CONFIDENTIAL: Unclaimed Inheritance Funds - USD $4,500,000.00
Date: Fri, 19 Jan 2024 07:33:15 +0100
Message-ID: <webmail-34567@ng-ministry.org>
Return-Path: <ahmed.mohammed@ng-ministry.org>
Authentication-Results: mx.victim-mail.com;
       dkim=fail reason="no signature";
       spf=fail (domain of ng-ministry.org does not designate 41.58.220.100 as permitted sender);
       dmarc=fail (p=REJECT)
Received-SPF: fail (domain of ng-ministry.org does not designate 41.58.220.100 as permitted sender) client-ip=41.58.220.100;
X-Originating-IP: [41.58.220.100]
Content-Type: text/plain; charset="UTF-8"

CONFIDENTIAL BUSINESS PROPOSAL

Dear Friend,

I am Barrister Ahmed Mohammed, a senior partner at Mohammed & Associates Legal Firm, Lagos, Nigeria. I am contacting you regarding an unclaimed inheritance fund of USD $4,500,000.00 (Four Million Five Hundred Thousand US Dollars) deposited in a security vault by my late client, Mr. James Williams, a foreign national who passed away in 2019 without any known next of kin.

After extensive search and investigation, I have decided to contact you as a trustworthy individual to claim these funds as the next of kin. This is completely legal and risk-free, and I assure you that this transaction is 100% safe.

You will receive 40% of the total funds ($1,800,000.00) as your share, while 50% will be for me and my associates, and 10% will cover all expenses.

To proceed, please provide the following information:
1. Your full name
2. Your phone number
3. Your bank account details for the transfer
4. A copy of your international passport or ID

Please respond to my private email: barrister.ahmed.private@gmail.com

I await your urgent response. Time is of the essence as the bank has given a deadline of 30 days.

Trust me on this matter and keep this between us only.

Best Regards,
Barrister Ahmed Mohammed
Mohammed & Associates Legal Firm
Lagos, Nigeria
Tel: +234-805-123-4567`
  },
  {
    id: 'sample-7',
    name: '🟢 Newsletter / Marketing Email',
    category: 'legitimate',
    raw: `Received: from mta1.marketing-platform.com (mta1.marketing-platform.com [54.240.10.50])
        by mx.recipient-domain.com with ESMTPS id M1234567;
        Sat, 20 Jan 2024 10:00:05 -0500
Authentication-Results: mx.recipient-domain.com;
       dkim=pass header.i=@techcompany.com;
       spf=pass smtp.mailfrom=bounce@techcompany.com;
       dmarc=pass header.from=techcompany.com
DKIM-Signature: v=1; a=rsa-sha256; d=techcompany.com; s=sel1; b=validSignature123
From: TechCompany Newsletter <newsletter@techcompany.com>
To: subscriber@recipient-domain.com
Subject: Weekly Tech Digest - AI Trends & Product Updates
Date: Sat, 20 Jan 2024 15:00:02 +0000
Message-ID: <newsletter-20240120@techcompany.com>
Return-Path: <bounce@techcompany.com>
List-Unsubscribe: <https://techcompany.com/unsubscribe?id=subscriber123>
Content-Type: text/html; charset="UTF-8"

Weekly Tech Digest

Hi there!

Here's your weekly roundup of the latest in technology:

📱 Product Updates
- Version 3.2 of our mobile app is now available with improved performance
- New dashboard features for enterprise customers

🤖 AI & Machine Learning
- Our latest research paper on natural language processing has been published
- Join our upcoming webinar on AI ethics - Register at https://techcompany.com/webinars

💡 Tips & Tutorials
- Getting started with our API: https://docs.techcompany.com/api-guide
- Best practices for data security: https://blog.techcompany.com/security-best-practices

You're receiving this email because you subscribed to TechCompany Newsletter.
Unsubscribe: https://techcompany.com/unsubscribe?id=subscriber123
Manage preferences: https://techcompany.com/preferences

TechCompany Inc.
123 Innovation Drive, San Francisco, CA 94105`
  },
];
