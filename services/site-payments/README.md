# site-payments

Independent asynchronous payment/account library used by the SeeYourSEO website server. It uses the existing Linux MariaDB service, PayPal Orders v2, and PayPal signature-verified webhooks. Checkout confirms the email by asking the buyer to enter it twice; no email is sent.

## Launch pricing proposal

One-time scan credits, not subscriptions:

| Plan | Price | Pages per scan |
| --- | ---: | ---: |
| Starter | $4.99 | 100 |
| Standard | $9.99 | 500 |
| Deep scan | $24.99 | 2,000 |

New paid plans are paused in the website UI. Free scans have no fixed free-tier page cap; actual crawl size is bounded by the configured service capacity. These prices describe the existing legacy payment plans and are not currently offered. Each earlier successful payment adds one scan credit. Reports keep the current 20-minute retention.

## Configuration

See [`backend/.env.example`](../../backend/.env.example) for the required environment variable names. The service reads environment variables first, then `~/.config/seeyourseo/payments.env` (or the path in `PAYMENTS_ENV_FILE`). Use a dedicated database and restricted database user, separate from any other application databases. The application creates its own payment/account tables on startup and never reads or writes another app's tables.

The password, PayPal secret, and database URL belong in the server's private environment file with mode `600`, never in Git or the frontend.

PayPal should first use `PAYPAL_MODE=sandbox`. Configure the sandbox webhook to call `POST /api/payments/webhook` and subscribe to `PAYMENT.CAPTURE.COMPLETED`. The server verifies every webhook signature and checks the captured amount, currency, and order reference before granting an account credit. Do not switch `PAYPAL_MODE=live` until the merchant profile, tax/refund terms, email sender, and live webhook have been configured.

## Flow

1. The buyer selects a fixed server-side plan and enters their email address twice; the server rejects mismatched values and creates a short-lived checkout.
2. The website URL is entered later, when the buyer starts their scan.
3. The server creates a PayPal order with the server-selected price.
4. PayPal checkout approval is captured server-side; the capture amount, currency, order, and plan are checked.
5. A successful capture creates/updates the account, grants one scan credit, and starts an HttpOnly session. A verified webhook is an idempotent backup confirmation path.
6. Account sign-in accepts the purchase email only when a confirmed payment has an unused scan credit. When all credits are used, the account page directs the buyer to purchase another scan with that same email. No email is sent.
