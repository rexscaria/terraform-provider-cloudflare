---
page_title: "cloudflare_snippet_rules Resource - Cloudflare"
subcategory: ""
description: |-
  
---

# cloudflare_snippet_rules (Resource)



## Example Usage

```terraform
resource "cloudflare_snippet_rules" "example_snippet_rules" {
  zone_id = "9f1839b6152d298aca64c4e906b6d074"
  rules = [{
    expression = "ip.src eq 1.1.1.1"
    snippet_name = "my_snippet"
    description = "Execute my_snippet when IP address is 1.1.1.1."
    enabled = true
  }]
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `rules` (Attributes List) A list of snippet rules. (see [below for nested schema](#nestedatt--rules))
- `zone_id` (String) The unique ID of the zone.

### Read-Only

- `description` (String) An informative description of the rule.
- `enabled` (Boolean) Whether the rule should be executed.
- `expression` (String) The expression defining which traffic will match the rule.
- `id` (String) The unique ID of the rule.
- `last_updated` (String) The timestamp of when the rule was last modified.
- `snippet_name` (String) The identifying name of the snippet.

<a id="nestedatt--rules"></a>
### Nested Schema for `rules`

Required:

- `expression` (String) The expression defining which traffic will match the rule.
- `snippet_name` (String) The identifying name of the snippet.

Optional:

- `description` (String) An informative description of the rule.
- `enabled` (Boolean) Whether the rule should be executed.

Read-Only:

- `id` (String) The unique ID of the rule.
- `last_updated` (String) The timestamp of when the rule was last modified.


