resource "cloudflare_ruleset" "example_ruleset" {
  kind = "root"
  name = "My ruleset"
  phase = "http_request_firewall_custom"
  zone_id = "zone_id"
  description = "My ruleset to execute managed rulesets"
  rules = [{
    action = "block"
    action_parameters = {
      response = {
        content = <<EOT
        {
          "success": false,
          "error": "you have been blocked"
        }
        EOT
        content_type = "application/json"
        status_code = 400
      }
    }
    description = "Block when the IP address is not 1.1.1.1"
    enabled = true
    exposed_credential_check = {
      password_expression = "url_decode(http.request.body.form[\\\"password\\\"][0])"
      username_expression = "url_decode(http.request.body.form[\\\"username\\\"][0])"
    }
    expression = "ip.src ne 1.1.1.1"
    logging = {
      enabled = true
    }
    ratelimit = {
      characteristics = ["ip.src"]
      period = 60
      counting_expression = "http.request.body.raw eq \"abcd\""
      mitigation_timeout = 600
      requests_per_period = 1000
      requests_to_origin = true
      score_per_period = 400
      score_response_header_name = "my-score"
    }
    ref = "my_ref"
  }]
}
