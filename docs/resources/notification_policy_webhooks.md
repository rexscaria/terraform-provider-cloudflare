---
page_title: "cloudflare_notification_policy_webhooks Resource - Cloudflare"
subcategory: ""
description: |-
  
---

# cloudflare_notification_policy_webhooks (Resource)



## Example Usage

```terraform
resource "cloudflare_notification_policy_webhooks" "example_notification_policy_webhooks" {
  account_id = "023e105f4ecef8ad9ca31a8372d0c353"
  name = "Slack Webhook"
  url = "https://hooks.slack.com/services/Ds3fdBFbV/456464Gdd"
  secret = "secret"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `account_id` (String) The account id
- `name` (String) The name of the webhook destination. This will be included in the request body when you receive a webhook notification.
- `url` (String) The POST endpoint to call when dispatching a notification.

### Optional

- `secret` (String, Sensitive) Optional secret that will be passed in the `cf-webhook-auth` header when dispatching generic webhook notifications or formatted for supported destinations. Secrets are not returned in any API response body.

### Read-Only

- `created_at` (String) Timestamp of when the webhook destination was created.
- `id` (String) UUID
- `last_failure` (String) Timestamp of the last time an attempt to dispatch a notification to this webhook failed.
- `last_success` (String) Timestamp of the last time Cloudflare was able to successfully dispatch a notification using this webhook.
- `type` (String) Type of webhook endpoint.
Available values: "slack", "generic", "gchat".

## Import

Import is supported using the following syntax:

```shell
$ terraform import cloudflare_notification_policy_webhooks.example '<account_id>/<webhook_id>'
```
