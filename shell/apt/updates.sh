#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

function get_package_provider() {
  # Determine our package provider
  local os_type=$(grep ^ID_LIKE /etc/os-release | cut -f2 -d=)

  if [ "$os_type" = "debian" ]; then

    # Check if apt is installed
    local test_command=$(command -v apt)
    if [ -n "$($test_command | tr -d '[:space:]')" ]; then
      echo "apt"
    else

      # Check if apt-get is installed
      local test_command=$(command -v apt-get)
      if [ -n "$($test_command | tr -d '[:space:]')" ]; then
        echo "apt-get"
      else

        # Neither apt or apt-get exist
        echo "Can not find 'apt' or 'apt-get'"
        exit 1
      fi
    fi
  fi
}

function is_apt_lock() {
  lsof -t "/var/lib/apt/lists/lock" >/dev/null 2>&1 ||
  lsof -t "/var/lib/dpkg/lock-frontend" >/dev/null 2>&1 ||
  lsof -t "/var/lib/dpkg/lock" >/dev/null 2>&1
}

function wait_for_apt_unlock() {

  local apt_lock_max_wait_time=600
  local apt_retry_interval=10
  local wait_time=0
  
  while is_apt_lock; do
    if [ "$wait_time" -ge "$apt_lock_max_wait_time" ]; then
      echo "wait_for_apt_unlock: Timeout reached. Lock file is still present."
      exit 1
    fi
    echo "wait_for_apt_unlock: Waiting for apt lock file to be released..."
    sleep $apt_retry_interval
    wait_time=$((wait_time + $apt_retry_interval))
  done
}

function upgrade_packages() {

  case $package_provider in
    apt)
        wait_for_apt_unlock
        apt -qqy upgrade
      ;;

    apt-get)
        # The timeout is to prevent E: Unable to acquire the dpkg frontend lock
        wait_for_apt_unlock
        apt-get -qqy -o DPkg::Lock::Timeout=60 upgrade
      ;;

    *)
      echo "upgrade_packages: Unknown package provider."
      exit 1
      ;;
  esac

  if [ $? -ne 0 ]; then
    echo "upgrade_packages: 'apt' failed upgrading with exit code '$?'"
    exit 1
  fi
}

function update_packages() {

  case $package_provider in
    apt)
        wait_for_apt_unlock
        apt -qqy update
      ;;

    apt-get)
        wait_for_apt_unlock
        apt-get -qqy -o DPkg::Lock::Timeout=60 update
      ;;

    *)
      echo "update_packages: Unknown package provider."
      exit 1
      ;;
  esac

  if [ $? -ne 0 ]; then
    echo "update_packages: '$package_provider' failed updating with exit code '$?'"
    exit 1
  fi
}

function install_packages() {
  packages=$(printf "%s " "$@")

  case $package_provider in
    apt)
        wait_for_apt_unlock
        apt -qqy install $packages
      ;;

    apt-get)
        wait_for_apt_unlock
        apt-get -qqy -o DPkg::Lock::Timeout=60 install $packages
      ;;

    *)
      echo "install_packages: Unknown package provider."
      exit 1
      ;;
  esac

  if [ $? -ne 0 ]; then
    echo "install_packages: '$package_provider' failed installing packages with exit code '$?'"
    exit 1
  fi
}

function remove_packages() {
  packages=$(printf "%s " "$@")

  case $package_provider in
    apt)
        wait_for_apt_unlock
        apt -qqy remove $packages
      ;;

    apt-get)
        wait_for_apt_unlock
        apt-get -qqy -o DPkg::Lock::Timeout=60 remove $packages
      ;;

    *)
      echo "remove_packages: Unknown package provider."
      exit 1
      ;;
  esac

  if [ $? -ne 0 ]; then
    echo "remove_packages: '$package_provider' failed removing packages with exit code '$?'"
    exit 1
  fi
}

package_provider=$(get_package_provider)
wait_for_apt_unlock

# To perform an upgrade
# upgrade_packages

# To perform an update
# update_packages

# To install a package(s)
# install_packages wget curl nano zip

# To remove a package(s)
# remove_packages wget curl nano
