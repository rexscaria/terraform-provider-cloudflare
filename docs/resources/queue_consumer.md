---
page_title: "cloudflare_queue_consumer Resource - Cloudflare"
subcategory: ""
description: |-
  
---

# cloudflare_queue_consumer (Resource)



## Example Usage

```terraform
resource "cloudflare_queue_consumer" "example_queue_consumer" {
  account_id = "023e105f4ecef8ad9ca31a8372d0c353"
  queue_id = "023e105f4ecef8ad9ca31a8372d0c353"
  dead_letter_queue = "example-queue"
  script_name = "my-consumer-worker"
  settings = {
    batch_size = 50
    max_concurrency = 10
    max_retries = 3
    max_wait_time_ms = 5000
    retry_delay = 10
  }
  type = "worker"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `account_id` (String) A Resource identifier.
- `queue_id` (String) A Resource identifier.

### Optional

- `consumer_id` (String) A Resource identifier.
- `dead_letter_queue` (String)
- `script_name` (String) Name of a Worker
- `settings` (Attributes) (see [below for nested schema](#nestedatt--settings))
- `type` (String) Available values: "worker", "http_pull".

### Read-Only

- `created_on` (String)
- `script` (String) Name of a Worker

<a id="nestedatt--settings"></a>
### Nested Schema for `settings`

Optional:

- `batch_size` (Number) The maximum number of messages to include in a batch.
- `max_concurrency` (Number) Maximum number of concurrent consumers that may consume from this Queue. Set to `null` to automatically opt in to the platform's maximum (recommended).
- `max_retries` (Number) The maximum number of retries
- `max_wait_time_ms` (Number) The number of milliseconds to wait for a batch to fill up before attempting to deliver it
- `retry_delay` (Number) The number of seconds to delay before making the message available for another attempt.
- `visibility_timeout_ms` (Number) The number of milliseconds that a message is exclusively leased. After the timeout, the message becomes available for another attempt.


