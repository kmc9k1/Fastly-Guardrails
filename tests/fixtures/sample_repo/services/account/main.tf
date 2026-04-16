resource "fastly_service_vcl" "account_prod" {
  name = "account-prod"
}

resource "fastly_backend" "backend1" {
  address = "10.22.33.44"
  ssl = false
  port = 80
}

resource "fastly_domain" "account_domain" {
  name    = "account.company.com"
  service = fastly_service_vcl.account_prod.id
}
