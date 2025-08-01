---
page_title: "cloudflare_hyperdrive_config Resource - Cloudflare"
subcategory: ""
description: |-
  
---

# cloudflare_hyperdrive_config (Resource)



## Example Usage

```terraform
resource "cloudflare_hyperdrive_config" "example_hyperdrive_config" {
  account_id = "023e105f4ecef8ad9ca31a8372d0c353"
  name = "example-hyperdrive"
  origin = {
    database = "postgres"
    host = "database.example.com"
    password = "password"
    port = 5432
    scheme = "postgres"
    user = "postgres"
  }
  caching = {
    disabled = true
  }
  mtls = {
    ca_certificate_id = "00000000-0000-0000-0000-0000000000"
    mtls_certificate_id = "00000000-0000-0000-0000-0000000000"
    sslmode = "verify-full"
  }
  origin_connection_limit = 60
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `account_id` (String) Define configurations using a unique string identifier.
- `name` (String)
- `origin` (Attributes) (see [below for nested schema](#nestedatt--origin))

### Optional

- `caching` (Attributes) (see [below for nested schema](#nestedatt--caching))
- `mtls` (Attributes) (see [below for nested schema](#nestedatt--mtls))
- `origin_connection_limit` (Number) The (soft) maximum number of connections the Hyperdrive is allowed to make to the origin database.

### Read-Only

- `created_on` (String) Defines the creation time of the Hyperdrive configuration.
- `id` (String) Define configurations using a unique string identifier.
- `modified_on` (String) Defines the last modified time of the Hyperdrive configuration.

<a id="nestedatt--origin"></a>
### Nested Schema for `origin`

Required:

- `database` (String) Set the name of your origin database.
- `host` (String) Defines the host (hostname or IP) of your origin database.
- `password` (String, Sensitive) Set the password needed to access your origin database. The API never returns this write-only value.
- `scheme` (String) Specifies the URL scheme used to connect to your origin database.
Available values: "postgres", "postgresql", "mysql".
- `user` (String) Set the user of your origin database.

Optional:

- `access_client_id` (String) Defines the Client ID of the Access token to use when connecting to the origin database.
- `access_client_secret` (String, Sensitive) Defines the Client Secret of the Access Token to use when connecting to the origin database. The API never returns this write-only value.
- `port` (Number) Defines the port (default: 5432 for Postgres) of your origin database.


<a id="nestedatt--caching"></a>
### Nested Schema for `caching`

Optional:

- `disabled` (Boolean) Set to true to disable caching of SQL responses. Default is false.
- `max_age` (Number) Specify the maximum duration items should persist in the cache. Not returned if set to the default (60).
- `stale_while_revalidate` (Number) Specify the number of seconds the cache may serve a stale response. Omitted if set to the default (15).


<a id="nestedatt--mtls"></a>
### Nested Schema for `mtls`

Optional:

- `ca_certificate_id` (String) Define CA certificate ID obtained after uploading CA cert.
- `mtls_certificate_id` (String) Define mTLS certificate ID obtained after uploading client cert.
- `sslmode` (String) Set SSL mode to 'require', 'verify-ca', or 'verify-full' to verify the CA.

## Import

Import is supported using the following syntax:

```shell
$ terraform import cloudflare_hyperdrive_config.example '<account_id>/<hyperdrive_id>'
```
