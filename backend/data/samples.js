export const SAMPLE_EMAILS = [
  {
    id: 'sample-bec-ceo-fraud',
    title: 'Executive BEC Wire Transfer Fraud (CEO Impersonation)',
    category: 'Business Email Compromise (BEC)',
    riskIndicator: 'CRITICAL',
    description: 'CEO display-name spoofing with reply-to redirection targeting CFO for an urgent confidential wire transfer.',
    rawEmail: `Received: from mail-relay.internal.corp [10.0.0.5] by mx.destination.com with ESMTP id q491823 for <cfo@enterprise-corp.com>; Fri, 04 Sep 2026 14:22:18 -0400
Received: from unknown (HELO webmail-direct.net) [102.89.23.14] by mail-relay.internal.corp with ESMTPS id abc192847; Fri, 04 Sep 2026 14:22:12 -0400
Authentication-Results: mx.destination.com;
  spf=softfail (sender IP 102.89.23.14 is not in enterprise-corp.com SPF);
  dkim=none;
  dmarc=fail (p=quarantine)
Return-Path: <bounce-notice-992@webmail-direct.net>
From: "David Marcus (CEO & President)" <ceo.office.direct@gmail.com>
Reply-To: "David Marcus" <dmarcus.executive.private@webmail-direct.net>
To: <cfo@enterprise-corp.com>
Subject: URGENT & STRICTLY CONFIDENTIAL: Immediate Acquisition Wire Transfer Required
Date: Fri, 04 Sep 2026 14:21:55 -0400
Message-ID: <9832104.20260904@webmail-direct.net>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Hi Mark,

I am currently in an all-day confidential executive board session regarding the strategic acquisition of Project Apex. 

We need to finalize the initial escrow payment today before 5:00 PM EST to lock in the terms. Can you immediately process an expedited international wire transfer of $248,500 to our legal counsel's escrow account? 

Please do not call my office line as my phone is on silent in the boardroom. Reply directly to this email and I will send the beneficiary wiring coordinates and legal agreement right away.

This requires your immediate and discrete attention.

Best regards,

David Marcus
Chief Executive Officer & President
Enterprise Global Holdings Ltd.
Direct Mobile: +1 (202) 555-0199
`
  },
  {
    id: 'sample-phish-m365-harvest',
    title: 'Microsoft 365 Credential Harvester (Typosquatted Domain)',
    category: 'Phishing / Credential Theft',
    riskIndicator: 'CRITICAL',
    description: 'Deceptive account suspension warning with homoglyph domain micros0ft-portal.xyz and credential lure.',
    rawEmail: `Received: from mx.google.com [172.217.194.27] by destination-mx.net with ESMTPS id g91283 for <analyst@company.org>; Sat, 05 Sep 2026 08:14:02 +0000
Received: from vps-node88.cloud-host.biz [45.142.214.99] by mx.google.com with ESMTP id m123498 for <analyst@company.org>; Sat, 05 Sep 2026 08:13:58 +0000
Authentication-Results: destination-mx.net;
  spf=fail (sender IP 45.142.214.99 is not authorized for microsoft.com);
  dkim=fail header.d=micros0ft-portal.xyz;
  dmarc=fail
From: "Microsoft 365 Security Operations" <security-alerts@micros0ft-portal.xyz>
To: <analyst@company.org>
Subject: Action Required: Your Microsoft 365 Account Will Be Terminated in 24 Hours
Date: Sat, 05 Sep 2026 08:13:50 +0000
Message-ID: <alert-88194@micros0ft-portal.xyz>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<body>
<div style="font-family: Arial, sans-serif; max-width: 600px; padding: 20px; border: 1px solid #e0e0e0;">
  <div style="color: #0078d4; font-size: 22px; font-weight: bold; margin-bottom: 15px;">
    Microsoft Cloud Security
  </div>
  <p>Dear User,</p>
  <p>We detected unusual sign-in activity and multiple failed password attempts from an unrecognized IP address in Moscow, Russia.</p>
  <p>To safeguard your organizational cloud assets, your account access has been scheduled for permanent suspension within <strong>24 hours</strong>.</p>
  <p style="margin: 25px 0;">
    <a href="http://45.142.214.99/auth/login.php?user=analyst@company.org" style="background-color: #0078d4; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
      Verify Account & Keep Password
    </a>
  </p>
  <p style="font-size: 12px; color: #777;">If the button above does not work, visit your security dashboard at: <a href="http://45.142.214.99/auth/login.php">https://login.microsoftonline.com/common/oauth2/v2.0/authorize</a></p>
  <hr style="border: 0; border-top: 1px solid #eee; margin-top: 30px;">
  <p style="font-size: 11px; color: #999;">Microsoft Corporation, One Microsoft Way, Redmond, WA 98052 USA</p>
</div>
</body>
</html>
`
  },
  {
    id: 'sample-malware-invoice-trojan',
    title: 'Financial Trojan Invoice with Weaponized Macro Attachment',
    category: 'Malware Delivery',
    riskIndicator: 'CRITICAL',
    description: 'Fake QuickBooks overdue remittance notice with malicious .xlsm script attachment from bulletproof relay.',
    rawEmail: `Received: from mail-gw.target-corp.com [198.51.100.12] by internal-mail.target-corp.com with ESMTP id t91209; Thu, 03 Sep 2026 11:05:44 +0100
Received: from relay-node3.bulletproof-servers.ru [185.220.101.44] by mail-gw.target-corp.com with ESMTP id k091238; Thu, 03 Sep 2026 11:05:39 +0100
Authentication-Results: mail-gw.target-corp.com;
  spf=neutral;
  dkim=none;
  dmarc=none
From: "Intuit QuickBooks Billing Center" <remittance-dept@quickbooks-invoicing-service.top>
To: <accounts.payable@target-corp.com>
Subject: OVERDUE NOTICE: Remittance Invoice #INV-984210 is 45 Days Past Due
Date: Thu, 03 Sep 2026 11:05:30 +0100
Message-ID: <inv-2026-9812@quickbooks-invoicing-service.top>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_99182_981239.1725534330"

------=_Part_99182_981239.1725534330
Content-Type: text/plain; charset=UTF-8

Dear Accounting Department,

Our automated billing records indicate that Invoice #INV-984210 totaling $43,890.00 remains past due. 

Failure to remit payment or provide proof of transaction within 48 hours will result in automatic escalation to commercial debt collection and immediate suspension of vendor services.

Please find the itemized tax statement and electronic remittance slip attached to this notice.

Ensure macros are enabled in Microsoft Excel to calculate regional VAT exemptions.

Sincerely,
Accounts Receivable Operations
Intuit QuickBooks Commercial Solutions

------=_Part_99182_981239.1725534330
Content-Type: application/vnd.ms-excel.sheet.macroEnabled.12; name="PastDue_Invoice_Statement_984210.xlsm"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="PastDue_Invoice_Statement_984210.xlsm"

UEsDBBQAAAAIAKV6a1Vb...[MALICIOUS_VBA_PAYLOAD_SIMULATED_DATA_STRING_FOR_FORENSIC_ANALYSIS_PURPOSES]...AAA==
------=_Part_99182_981239.1725534330--
`
  },
  {
    id: 'sample-apt-impossible-travel',
    title: 'Nation-State / APT Relay Chain with Impossible Travel',
    category: 'State-Sponsored / Advanced Persistent Threat',
    riskIndicator: 'HIGH',
    description: 'Complex multi-relay evasion path traversing St. Petersburg, Bucharest, Frankfurt, and Virginia within 8 seconds.',
    rawEmail: `Received: from mail-edge.gov-defense.org [20.42.11.89] by mx.gov-defense.org with ESMTPS id d01982 for <director@gov-defense.org>; Wed, 02 Sep 2026 19:40:12 +0000
Received: from frankfurt-gw.transit-hub.de [50.110.9.1] by mail-edge.gov-defense.org with ESMTPS id f98213; Wed, 02 Sep 2026 19:40:09 +0000
Received: from bucharest-proxy.rom-net.ro [194.67.210.15] by frankfurt-gw.transit-hub.de with ESMTP id b77123; Wed, 02 Sep 2026 19:40:06 +0000
Received: from origin-c2.spb-infrastructure.ru [185.220.101.5] by bucharest-proxy.rom-net.ro with ESMTP id spb001; Wed, 02 Sep 2026 19:40:04 +0000
Authentication-Results: mx.gov-defense.org;
  spf=fail (sender IP 185.220.101.5 not authorized);
  dkim=fail (signature altered in transit);
  dmarc=fail (p=reject)
From: "Defense Logistics Agency (DLA)" <procurement@dla.mil>
Reply-To: <contract-liaison@secure-gov-portal.buzz>
To: <director@gov-defense.org>
Subject: RESTRICTED // FY27 Strategic Defense Supply Chain RFP Solicitation
Date: Wed, 02 Sep 2026 19:39:55 +0000
Message-ID: <dla-rfp-20260902-8812@dla.mil>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

CLASSIFICATION: RESTRICTED / OFFICIAL USE ONLY

To all authorized Department contractors,

Please review the attached procurement specifications and secure cryptographic token submission instructions for the upcoming FY27 Defense Materials Modernization contract.

Technical bid documentation must be submitted via the external liaison relay portal:
hxxps://secure-gov-portal[.]buzz/dla-auth/token-submission/

Any questions should be routed strictly through the designated liaison contract officer.

Defense Logistics Agency (DLA)
Headquarters Logistics Operations
Fort Belvoir, Virginia
`
  },
  {
    id: 'sample-clean-corp-newsletter',
    title: 'Verified Corporate Engineering Update (Clean Baseline)',
    category: 'Legitimate Corporate Communication',
    riskIndicator: 'LOW',
    description: 'Legitimate enterprise engineering newsletter with full SPF PASS, DKIM PASS, and DMARC PASS.',
    rawEmail: `Received: from mail-wr1-f48.google.com [209.85.128.48] by mx.recipient-corp.com with ESMTPS id h9120938 for <dev-team@recipient-corp.com>; Fri, 04 Sep 2026 16:30:10 -0700
Received: from 10.200.4.12 by mail-wr1-f48.google.com with SMTP id w12so12948wrq.5; Fri, 04 Sep 2026 16:30:08 -0700
Authentication-Results: mx.recipient-corp.com;
  spf=pass (google.com: domain of engineering-updates@techinnovations.com designates 209.85.128.48 as permitted sender) smtp.mailfrom=engineering-updates@techinnovations.com;
  dkim=pass header.i=@techinnovations.com header.s=google;
  dmarc=pass (p=reject sp=reject dis=none) header.from=techinnovations.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=techinnovations.com; s=google;
  h=from:to:subject:date:message-id:mime-version:content-type;
  bh=92kj8uG...==;
  b=AbCdEf...==
From: "Tech Innovations Engineering" <engineering-updates@techinnovations.com>
To: <dev-team@recipient-corp.com>
Subject: Tech Innovations Monthly Engineering Digest: Q3 Architecture Milestones
Date: Fri, 04 Sep 2026 16:30:00 -0700
Message-ID: <digest-q3-2026@techinnovations.com>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #333; line-height: 1.6;">
  <div style="max-width: 640px; margin: 0 auto; padding: 24px; background: #ffffff;">
    <h2 style="color: #1e293b; margin-top: 0;">Monthly Engineering Digest &mdash; September 2026</h2>
    <p>Hello Engineers,</p>
    <p>Here are the latest technical highlights from across our distributed engineering teams this month:</p>
    <ul>
      <li><strong>Distributed Caching:</strong> Reduced p99 API latencies by 42% using multi-region Edge KV nodes.</li>
      <li><strong>Security Hardening:</strong> Zero-trust mTLS rollout completed across all internal microservices.</li>
      <li><strong>Open Source:</strong> Our new forensic event streaming library has officially surpassed 1,000 GitHub stars.</li>
    </ul>
    <p>Read the full post and architecture diagrams on our tech blog: <a href="https://techinnovations.com/blog/2026/09/engineering-digest" style="color: #2563eb;">https://techinnovations.com/blog/2026/09/engineering-digest</a></p>
    <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;">
    <p style="font-size: 12px; color: #64748b;">You received this email because you are subscribed to the Tech Innovations Engineering Digest. To manage preferences, visit your account settings.</p>
  </div>
</body>
</html>
`
  }
];
