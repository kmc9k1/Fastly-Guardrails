resource "fastly_service_vcl" "checkout_prod" {
  name = "checkout-prod"
}

resource "fastly_backend" "checkout_primary_backend" {
  address = "checkout-origin.internal.company.net"
  port    = 443
  use_ssl = true
  shield  = "iad-va-us"
}

resource "fastly_domain" "checkout_domain" {
  name    = "shop.company.com"
  service = fastly_service_vcl.checkout_prod.id
}

resource "fastly_logging_https" "checkout_datadog" {
  name    = "checkout-datadog"
  url     = "https://logs.company.com/ingest"
  service = fastly_service_vcl.checkout_prod.id
}
