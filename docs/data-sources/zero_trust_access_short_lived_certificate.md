---
page_title: "cloudflare_zero_trust_access_short_lived_certificate Data Source - Cloudflare"
subcategory: ""
description: |-
  
---

# cloudflare_zero_trust_access_short_lived_certificate (Data Source)



## Example Usage

```terraform
data "cloudflare_zero_trust_access_short_lived_certificate" "example_zero_trust_access_short_lived_certificate" {
  app_id = "f174e90a-fafe-4643-bbbc-4a0ed4fc8415"
  account_id = "account_id"
  zone_id = "zone_id"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `app_id` (String) UUID.

### Optional

- `account_id` (String) The Account ID to use for this endpoint. Mutually exclusive with the Zone ID.
- `zone_id` (String) The Zone ID to use for this endpoint. Mutually exclusive with the Account ID.

### Read-Only

- `aud` (String) The Application Audience (AUD) tag. Identifies the application associated with the CA.
- `id` (String) The ID of the CA.
- `public_key` (String) The public key to add to your SSH server configuration.


