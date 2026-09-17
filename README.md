# Vercel Surface Scanner UI

This folder is the Vercel deployment package for the browser interface.

## Important architecture

Vercel hosts the UI and the small `/api/scan` proxy. The actual Python scanner, native TCP checks, and optional Nmap integration must run on a separate backend that you control. Vercel serverless functions cannot host the long-running Python scanner or arbitrary TCP scanning engine.

## Deploy

1. Deploy the `vercel-app` folder as the Vercel project root.
2. In Vercel project settings, add this environment variable:

```text
SCANNER_BACKEND_URL=https://your-scanner-backend.example.com
```

3. Deploy again.
4. Open the Vercel URL in a browser.

You can also add the variable with the Vercel CLI from this folder:

```powershell
npx vercel env add SCANNER_BACKEND_URL production
```

When prompted, enter the public HTTPS URL of your Python scanner backend, then redeploy:

```powershell
npx vercel --prod
```

`.env.example` shows the required variable name. Do not rename it and do not commit a real private URL or credential into that file.

The backend must expose the existing `POST /api/scan` endpoint and accept form fields named `target`, `ports`, `authorized`, `public-confirm`, and `approved-target`.

## Backend

Run the existing Python web service on a separately hosted machine:

```powershell
C:/Python313/python.exe -m surface_scanner web --host 0.0.0.0 --port 8765
```

Put the public HTTPS URL of that service in `SCANNER_BACKEND_URL`. Restrict the backend with a firewall, authentication at the hosting layer, and HTTPS. Keep the scanner's authorization and public-target allowlist controls enabled.

## Safety boundary

This deployment supports authorized discovery and enumeration only. It does not add credential harvesting, brute force, password spraying, exploitation, or unrestricted public scanning.
