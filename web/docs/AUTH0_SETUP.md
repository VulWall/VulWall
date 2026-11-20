# Auth0 Multi-Tenant Setup Guide

This guide explains how to configure Auth0 to include the `org_id` in JWT tokens for multi-tenant organization isolation.

## Overview

VulWall uses a multi-tenant architecture where:
- Each user belongs to exactly one organization
- The `org_id` is stored in the user's Auth0 `app_metadata`
- The `org_id` is included as a custom claim in JWT tokens
- All data access is automatically filtered by organization


Auth0 Actions are the modern way to customize authentication flows.

### Step 1: Create a Login Action

1. Go to your Auth0 Dashboard
2. Navigate to **Actions** → **Library**
3. Click **Build Custom**
4. Enter the following details:
   - **Name**: `Add Organization Claim`
   - **Trigger**: `Login / Post Login`
   - **Runtime**: `Node 18` (or latest)

### Step 2: Add the Action Code

Paste the following code:

```javascript
/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://vulwall.com';

  // Get org_id from app_metadata
  const orgId = event.user.app_metadata?.org_id;

  if (orgId) {
    // Add custom claim to both ID token and Access token
    api.idToken.setCustomClaim(`${namespace}/org_id`, orgId);
    api.accessToken.setCustomClaim(`${namespace}/org_id`, orgId);
  } else {
    console.log(`Warning: User ${event.user.user_id} has no org_id in app_metadata`);
  }
};
```

### Step 3: Deploy the Action

1. Click **Deploy** to save and activate the action
2. Go to **Actions** → **Triggers** → **post-login**
3. Drag your `Add Organization Claim` action from the right sidebar into the flow
4. Place it **after** the "Start" node
5. Click **Apply**

### Step 4: Verify the Setup

After logging in, the JWT token will contain:

```json
{
  "https://vulwall.com/org_id": "your-org-id-here",
  "sub": "auth0|123456",
  "email": "user@example.com",
  ...
}
```

## How It Works in VulWall

### 1. First Login - User Creation

When a user logs in for the first time:

```
User logs in → Auth0 authenticates → OnTokenValidated fires
→ User not found in DB → Create new User with generated org_id
→ Sync org_id to Auth0 app_metadata → User redirected to dashboard
```

**Code location**: `src/Extensions/ServiceCollectionExtensions.cs`

### 2. Subsequent Logins - Fast Path

```
User logs in → Auth0 authenticates → Custom claim added by Action
→ JWT contains org_id → OrganizationContext reads from claim
→ All DB queries automatically filtered by org_id
```

**Code location**: `src/Common/Services/Organization/OrganizationContext.cs`

### 3. Fallback Mechanism

If org_id claim is missing (e.g., Action not configured yet):

```
JWT has no org_id claim → OrganizationContext falls back to DB lookup
→ Finds user by Auth0 UserId → Returns org_id from User entity
→ Works but slower (extra DB query)
```

**Code location**: `src/Common/Services/Organization/OrganizationContext.cs`

---

## Security Architecture

### Multi-Layer Defense

VulWall implements defense-in-depth security:

#### Layer 1: Auth0 Token
- `org_id` stored in signed JWT (cannot be tampered with)

#### Layer 2: OrganizationContext Service
- Extracts org_id from claims or database
- Throws exception if org_id cannot be determined

**Code**: `src/Common/Services/Organization/OrganizationContext.cs`

#### Layer 3: OrgScopedRepository
- Automatically injects org_id filter into ALL queries
- Validates ownership on updates/deletes
- Auto-sets org_id on entity creation

**Code**: `src/Data/Base/OrgScopedRepository.cs`

#### Layer 4: MongoDB Indexes
- Indexed on `org_id` for performance
- Ensures fast queries even with millions of records

### What's Protected

✅ **Assets** - Org-scoped (domains, IPs)
✅ **Discoveries** - Org-scoped (subdomains, ports, services)
✅ **AuditLogs** - Org-scoped (activity logs)
❌ **Users** - NOT org-scoped (looked up by Auth0 UserId during login)

For global data (CVEs, threat intel), use `BaseMongoRepository` directly.

---

## Testing the Implementation

### 1. Create Two Test Users

In Auth0 Dashboard:
1. Create `user1@test.com`
2. Create `user2@test.com`

### 2. Login as Each User

- Each will get a unique `org_id` auto-generated
- Check browser DevTools → Application → Cookies → `auth0` cookie
- Decode JWT at [jwt.io](https://jwt.io) - you should see `https://vulwall.com/org_id`

### 3. Verify Isolation

1. Login as User 1, create an asset
2. Note the asset ID from URL
3. Logout
4. Login as User 2
5. Try to access User 1's asset by URL manipulation
6. ✅ Should get "Not Found" or redirected to index

---

## Troubleshooting

### Org ID not in token

**Symptoms**: `OrganizationContext` logs "org_id not found in claims, falling back to database"

**Solutions**:
1. Check Auth0 Action is deployed and in the Login flow
2. Verify namespace is `https://vulwall.com` (not `http://`)
3. Check browser DevTools → Decode JWT → Look for custom claim

### "User has no organization assigned" error

**Symptoms**: User can login but gets exception

**Solutions**:
1. Check database - user record might be corrupt
2. Delete user from MongoDB and Auth0, create fresh
3. Check `SyncUserOnLogin` logs for errors

### Users can see other org's data

**Symptoms**: Data isolation not working

**Solutions**:
1. Verify repository extends `OrgScopedRepository` (except UserRepository)
2. Check logs - `OrganizationContext` should log org_id on requests
3. Add breakpoint in `OrgScopedRepository.GetAllAsync()` - verify org filter applied

---

## API Reference

### IOrganizationContext

```csharp
public interface IOrganizationContext
{
    /// <summary>
    /// Gets org_id for current authenticated user.
    /// Throws if user not authenticated or org_id missing.
    /// </summary>
    Task<string> GetCurrentOrgIdAsync();
}
```

**Usage**:
```csharp
public class MyService
{
    private readonly IOrganizationContext _orgContext;

    public async Task DoSomething()
    {
        var orgId = await _orgContext.GetCurrentOrgIdAsync();
        // Use orgId for custom queries
    }
}
```

### OrgScopedRepository

All methods automatically filter by org_id:

```csharp
// Gets ALL assets for current user's org (not ALL orgs)
var assets = await assetsRepository.GetAllAsync();

// Gets asset ONLY if it belongs to current user's org
var asset = await assetsRepository.GetByIdAsync(id);

// Auto-sets org_id before creating
await assetsRepository.CreateAsync(newAsset);

// Throws UnauthorizedAccessException if asset belongs to different org
await assetsRepository.UpdateAsync(asset);
await assetsRepository.DeleteAsync(assetId);
```

---

## Future Enhancements

### 1. Organization Management UI

Allow users to:
- Update organization profile
- Invite team members
- See organization usage stats

### 2. Cross-Organization Sharing

Optionally allow sharing specific reports/assets across orgs with permissions.

### 3. Organization Roles

Add role-based access control (RBAC) within organizations:
- Admin, Member, Viewer roles
- Different permissions per role

### 4. Multi-Organization Users

Allow a single user to belong to multiple organizations:
- Add organization switcher in UI
- Store org memberships in junction table
- Update OrganizationContext to support org switching

---

## Production Checklist

Before deploying to production:

- [ ] Auth0 Action deployed and in Login flow
- [ ] Tested with multiple users in different orgs
- [ ] Verified data isolation (cross-org access attempts blocked)
- [ ] MongoDB indexes created on `org_id` fields
- [ ] Monitoring/alerting set up for `UnauthorizedAccessException`
- [ ] Backup/restore procedures tested
- [ ] Rate limiting configured on Auth0 Management API calls

---

## Support

For issues or questions:
- Review Auth0 logs in Dashboard → Monitoring → Logs
- See implementation code in `src/Common/Services/`

**Security Note**: Never log `org_id` values in production logs that might be publicly accessible.
