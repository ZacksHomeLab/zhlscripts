variable "azuread_tenant_id" {
    type = string
    description = "The Tenant ID within Azure."

    validation {
        condition     = can(regex("^[0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12}$", var.azuread_tenant_id))
        error_message = "The value of 'azuread_tenant_id' must match abcd1234-1234-abcd-123412341234"
    }

    nullable = false
}

variable "azuread_app_name" {
    type = string
    description = "The Tenant ID within Azure."

    nullable = false
}

variable "master_vm_name" {
    type = string
    description = "The name of the Master Node's Virtual Machine."

    validation {
        condition = length(var.master_vm_name) > 0 && length(var.master_vm_name) <= 64
        error_message = "Master VM Name cannot be null and must be less than 64 characters."
    }

    nullable = false
}

variable "master_vm_agent" {
    type = number
    description = "Set to 1 to enable the QEMU Guest Agent. Note, you must run the qemu-guest-agent daemon in the guest for this to have any effect."
    default = 0

    validation {
        condition = var.master_vm_agent >= 0 && var.master_vm_agent <= 1
        error_message = "Set to 1 to enable the QEMU Guest Agent or 0 to disable."
    }

    nullable = false
}

variable "master_storage_enable_backup" {
    type = number
    description = "Enable backup for this hard disk?"
    default = 1

    validation {
        condition = var.master_storage_enable_backup == 0 || var.master_storage_enable_backup == 1
        error_message = "Set 'master_storage_enable_backup' to '1' to enable backups or '0' to disable."
    }

    nullable = false
}

variable "master_storage_type" {
    type = string
    description = "The type of Storage."
    default = "virtio"

    validation {
        condition     = contains(["virtio", "scsi", "ide", "sata"], var.master_storage_type)
        error_message = "You must specify a storage type. Your options are: virtio, scsi, ide, or sata"
    }

    nullable = false
}