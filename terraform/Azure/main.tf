# Retrieve domain information
data "azuread_domains" "zacksHomeLab" {
  only_initial = true
}

resource "azuread_application" "azureApp" {
  display_name = var.azuread_app_name
}

# Create a service principal
resource "azuread_service_principal" "servicePrincipal" {
  application_id = azuread_application.azureApp.application_id
}