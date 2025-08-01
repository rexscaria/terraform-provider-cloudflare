---
page_title: "cloudflare_workers_scripts Data Source - Cloudflare"
subcategory: ""
description: |-
  
---

# cloudflare_workers_scripts (Data Source)



## Example Usage

```terraform
data "cloudflare_workers_scripts" "example_workers_scripts" {
  account_id = "023e105f4ecef8ad9ca31a8372d0c353"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `account_id` (String) Identifier.

### Optional

- `max_items` (Number) Max items to fetch, default: 1000

### Read-Only

- `result` (Attributes List) The items returned by the data source (see [below for nested schema](#nestedatt--result))

<a id="nestedatt--result"></a>
### Nested Schema for `result`

Read-Only:

- `created_on` (String) When the script was created.
- `etag` (String) Hashed script content, can be used in a If-None-Match header when updating.
- `has_assets` (Boolean) Whether a Worker contains assets.
- `has_modules` (Boolean) Whether a Worker contains modules.
- `id` (String) The id of the script in the Workers system. Usually the script name.
- `logpush` (Boolean) Whether Logpush is turned on for the Worker.
- `modified_on` (String) When the script was last modified.
- `placement` (Attributes) Configuration for [Smart Placement](https://developers.cloudflare.com/workers/configuration/smart-placement). (see [below for nested schema](#nestedatt--result--placement))
- `placement_mode` (String, Deprecated) Enables [Smart Placement](https://developers.cloudflare.com/workers/configuration/smart-placement).
Available values: "smart".
- `placement_status` (String, Deprecated) Status of [Smart Placement](https://developers.cloudflare.com/workers/configuration/smart-placement).
Available values: "SUCCESS", "UNSUPPORTED_APPLICATION", "INSUFFICIENT_INVOCATIONS".
- `tail_consumers` (Attributes Set) List of Workers that will consume logs from the attached Worker. (see [below for nested schema](#nestedatt--result--tail_consumers))
- `usage_model` (String) Usage model for the Worker invocations.
Available values: "standard".

<a id="nestedatt--result--placement"></a>
### Nested Schema for `result.placement`

Read-Only:

- `last_analyzed_at` (String) The last time the script was analyzed for [Smart Placement](https://developers.cloudflare.com/workers/configuration/smart-placement).
- `mode` (String) Enables [Smart Placement](https://developers.cloudflare.com/workers/configuration/smart-placement).
Available values: "smart".
- `status` (String) Status of [Smart Placement](https://developers.cloudflare.com/workers/configuration/smart-placement).
Available values: "SUCCESS", "UNSUPPORTED_APPLICATION", "INSUFFICIENT_INVOCATIONS".


<a id="nestedatt--result--tail_consumers"></a>
### Nested Schema for `result.tail_consumers`

Read-Only:

- `environment` (String) Optional environment if the Worker utilizes one.
- `namespace` (String) Optional dispatch namespace the script belongs to.
- `service` (String) Name of Worker that is to be the consumer.


