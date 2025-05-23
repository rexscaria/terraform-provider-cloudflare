
    resource "cloudflare_zero_trust_access_application" "%[1]s" {
      name             = "%[1]s-updated"
      zone_id          = "%[3]s"
      domain           = "%[1]s.%[2]s"
      type             = "self_hosted"

      cors_headers = {
  allowed_methods = ["GET"]
        allowed_origins = ["*"]
        allow_credentials = true
}
  }
  