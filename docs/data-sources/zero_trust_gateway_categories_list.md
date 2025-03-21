---
page_title: "cloudflare_zero_trust_gateway_categories_list Data Source - Cloudflare"
subcategory: ""
description: |-
  
---

# cloudflare_zero_trust_gateway_categories_list (Data Source)



## Example Usage

```terraform
data "cloudflare_zero_trust_gateway_categories_list" "example_zero_trust_gateway_categories_list" {
  account_id = "023e105f4ecef8ad9ca31a8372d0c353"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `account_id` (String) Identifier

### Optional

- `max_items` (Number) Max items to fetch, default: 1000

### Read-Only

- `result` (Attributes List) The items returned by the data source (see [below for nested schema](#nestedatt--result))

<a id="nestedatt--result"></a>
### Nested Schema for `result`

Read-Only:

- `beta` (Boolean) True if the category is in beta and subject to change.
- `class` (String) Which account types are allowed to create policies based on this category. `blocked` categories are blocked unconditionally for all accounts. `removalPending` categories can be removed from policies but not added. `noBlock` categories cannot be blocked.
Available values: "free", "premium", "blocked", "removalPending", "noBlock".
- `description` (String) A short summary of domains in the category.
- `id` (Number) The identifier for this category. There is only one category per ID.
- `name` (String) The name of the category.
- `subcategories` (Attributes List) All subcategories for this category. (see [below for nested schema](#nestedatt--result--subcategories))

<a id="nestedatt--result--subcategories"></a>
### Nested Schema for `result.subcategories`

Read-Only:

- `beta` (Boolean) True if the category is in beta and subject to change.
- `class` (String) Which account types are allowed to create policies based on this category. `blocked` categories are blocked unconditionally for all accounts. `removalPending` categories can be removed from policies but not added. `noBlock` categories cannot be blocked.
Available values: "free", "premium", "blocked", "removalPending", "noBlock".
- `description` (String) A short summary of domains in the category.
- `id` (Number) The identifier for this category. There is only one category per ID.
- `name` (String) The name of the category.


