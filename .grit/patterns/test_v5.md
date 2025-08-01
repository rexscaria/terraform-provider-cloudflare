# Test Cloudflare v5

```grit
language hcl

cloudflare_terraform_v5()
```

## test: basic rewrite

```hcl
resource "cloudflare_access_policy" "test_policy" {
  account_id     = "f037e56e89293a057740de681ac9abbe"
  name           = "staging policy"
  decision       = "allow"

  require {
    any_valid_service_token = true
  }
}
```

```hcl
resource "cloudflare_access_policy" "test_policy" {
  account_id     = "f037e56e89293a057740de681ac9abbe"
  name           = "staging policy"
  decision       = "allow"

  require =[{
    any_valid_service_token = true
  }]
}
```

## test: list collapsing

Multiple blocks should be collapsed into a single list attribute.

```hcl
resource "cloudflare_access_policy" "test_policy" {
  account_id     = "f037e56e89293a057740de681ac9abbe"
  name           = "staging policy"
  decision       = "allow"

  include {
    email = ["test@example.com"]
  }

  include {
    email = ["someone@example.com"]
  }

  exclude {
    email = ["bad@other.com"]
  }
}
```

```hcl
resource "cloudflare_access_policy" "test_policy" {
  account_id     = "f037e56e89293a057740de681ac9abbe"
  name           = "staging policy"
  decision       = "allow"

  include = [{
    email = ["test@example.com"]
  },
  {
    email = ["someone@example.com"]
  }]


  exclude = [{
    email = ["bad@other.com"]
  }]
}
```

## test: nested blocks

Nested blocks must also be rewritten.

```hcl
resource "cloudflare_access_policy" "test_policy" {
  account_id     = "f037e56e89293a057740de681ac9abbe"
  name           = "staging policy"
  decision       = "allow"

  require {
    azure {
      id = ["1234"]
    }
  }
}
```

```hcl
resource "cloudflare_access_policy" "test_policy" {
  account_id     = "f037e56e89293a057740de681ac9abbe"
  name           = "staging policy"
  decision       = "allow"

  require = [{
    azure = {
      id = ["1234"]
    }
  }]
}
```

## test-rulesets: collapse list, nested blocks mapped
```hcl
resource "cloudflare_ruleset" "test_ruleset" {
  kind        = "zone"
  name        = "test"
  phase       = "http_request_dynamic_redirect"
  zone_id     = "f037e56e89293a057740de681ac9abbe"

  rules {
    action = "redirect"
    action_parameters {
      from_value {
        preserve_query_string = true
        status_code           = 301
        target_url {
          value = "https://example.com"
        }
      }
    }
    description = "foo"
    enabled     = false
    expression  = "(http.host in {\"www.foo.com\"} and (http.user_agent contains \"foo\" or http.user_agent contains \"foo\"))"
    ref         = "f037e56e89293a057740de681ac9abbe"
  }
  rules {
    action = "redirect"
    action_parameters {
      from_value {
        preserve_query_string = false
        status_code           = 301
        target_url {
          value = "https://example.com"
        }
      }
    }
    description = "foo"
    enabled     = false
    expression  = "(http.host in {\"www.foo.com\"} and (http.user_agent contains \"foo\" or http.user_agent contains \"foo\"))"
    ref         = "f037e56e89293a057740de681ac9abbe"
  }
  rules {
    action = "execute"
    action_parameters {
      id = "f037e56e89293a057740de681ac9abbe"
      overrides {
        enabled = true
        categories {
          category = "drupal"
          action   = "managed_challenge"
        }
        categories {
          category = "command-injection"
          action   = "block"
        }
        categories {
          category = "apache-struts"
          action   = "challenge"
        }
      }
    }
    enabled    = true
    expression = "true"
  }
}
```
```hcl
resource "cloudflare_ruleset" "test_ruleset" {
  kind    = "zone"
  name    = "test"
  phase   = "http_request_dynamic_redirect"
  zone_id = "f037e56e89293a057740de681ac9abbe"

  rules = [{
    action = "redirect"
    action_parameters = {
      from_value = {
        preserve_query_string = true
        status_code           = 301
        target_url = {
          value = "https://example.com"
        }
      }
    }
    description = "foo"
    enabled     = false
    expression  = "(http.host in {\"www.foo.com\"} and (http.user_agent contains \"foo\" or http.user_agent contains \"foo\"))"
    ref         = "f037e56e89293a057740de681ac9abbe"
    },
    {
      action = "redirect"
      action_parameters = {
        from_value = {
          preserve_query_string = false
          status_code           = 301
          target_url = {
            value = "https://example.com"
          }
        }
      }
      description = "foo"
      enabled     = false
      expression  = "(http.host in {\"www.foo.com\"} and (http.user_agent contains \"foo\" or http.user_agent contains \"foo\"))"
      ref         = "f037e56e89293a057740de681ac9abbe"
    },
    {
      action = "execute"
      action_parameters = {
        id = "f037e56e89293a057740de681ac9abbe"
        overrides = {
          enabled = true
          categories = [{
            category = "drupal"
            action   = "managed_challenge"
            },
            {
              category = "command-injection"
              action   = "block"
            },
            {
              category = "apache-struts"
              action   = "challenge"
          }]


        }
      }
      enabled    = true
      expression = "true"
  }]
}
```
## test: single blocks

Blocks which are not lists should become attribute objects. This is based on the schema, not the number of blocks.

```hcl
resource "cloudflare_load_balancer_pool" "example" {
  account_id = "f037e56e89293a057740de681ac9abbe"
  name       = "example-pool"
  origins {
    name    = "example-1"
    address = "192.0.2.1"
    enabled = false
    header {
      header = "Host"
      values = ["example-1"]
    }
  }
  origins {
    name    = "example-2"
    address = "192.0.2.2"
    header {
      header = "Host"
      values = ["example-2"]
    }
  }
  latitude           = 55
  longitude          = -12
  description        = "example load balancer pool"
  enabled            = false
  minimum_origins    = 1
  notification_email = "someone@example.com"
  load_shedding {
    default_percent = 55
    default_policy  = "random"
    session_percent = 12
    session_policy  = "hash"
  }
  origin_steering {
    policy = "random"
  }
}
```

```hcl
resource "cloudflare_load_balancer_pool" "example" {
  account_id = "f037e56e89293a057740de681ac9abbe"
  name       = "example-pool"
  origins = [{
    name    = "example-1"
    address = "192.0.2.1"
    enabled = false
    header = {
      header = "Host"
      values = ["example-1"]
    }
  },
  {
    name    = "example-2"
    address = "192.0.2.2"
    header = {
      header = "Host"
      values = ["example-2"]
    }
  }]
  latitude           = 55
  longitude          = -12
  description        = "example load balancer pool"
  enabled            = false
  minimum_origins    = 1
  notification_email = "someone@example.com"
  load_shedding = {
    default_percent = 55
    default_policy  = "random"
    session_percent = 12
    session_policy  = "hash"
  }
  origin_steering = {
    policy = "random"
  }
}
```
