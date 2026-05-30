#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/install.sh [options]

Install rand-guard using the default FHS layout.

Options:
  --root DIR        Install under DIR instead of / for staging or tests.
  --source-dir DIR  Read artifacts from DIR instead of the repository root.
  --force           Replace an existing config.toml after creating a timestamp backup.
  --dry-run         Print the planned install actions without changing files.
  -h, --help        Show this help.

Expected source files:
  target/release/edr-user
  target/bpfel-unknown-none/release/edr-ebpf
  packaging/config/rand-guard.toml
  packaging/rules.d/sample-rules.toml
  packaging/systemd/rand-guard.service
USAGE
}

root="/"
source_dir=""
force=0
dry_run=0
missing_sources=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --root)
      root="${2:?--root requires a directory}"
      shift 2
      ;;
    --source-dir)
      source_dir="${2:?--source-dir requires a directory}"
      shift 2
      ;;
    --force)
      force=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "$source_dir" ]; then
  source_dir="$(cd -- "$script_dir/.." && pwd)"
else
  source_dir="$(cd -- "$source_dir" && pwd)"
fi

join_root() {
  local path="$1"
  if [ "$root" = "/" ]; then
    printf '%s\n' "$path"
  else
    printf '%s%s\n' "${root%/}" "$path"
  fi
}

run() {
  if [ "$dry_run" -eq 1 ]; then
    printf 'DRY-RUN:'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

install_file() {
  local mode="$1"
  local src="$2"
  local dst="$3"
  run install -m "$mode" "$src" "$dst"
}

require_source() {
  local path="$1"
  if [ ! -f "$path" ]; then
    echo "missing required source file: $path" >&2
    missing_sources=1
  fi
}

user_bin="$source_dir/target/release/edr-user"
ebpf_obj="$source_dir/target/bpfel-unknown-none/release/edr-ebpf"
default_config="$source_dir/packaging/config/rand-guard.toml"
sample_rules="$source_dir/packaging/rules.d/sample-rules.toml"
systemd_unit="$source_dir/packaging/systemd/rand-guard.service"

require_source "$user_bin"
require_source "$ebpf_obj"
require_source "$default_config"
require_source "$sample_rules"
require_source "$systemd_unit"

if [ "$missing_sources" -ne 0 ]; then
  echo "build or package rand-guard before running the installer" >&2
  exit 1
fi

bin_dir="$(join_root /usr/local/bin)"
lib_dir="$(join_root /usr/local/lib/rand-guard)"
config_dir="$(join_root /etc/rand-guard)"
rules_dir="$(join_root /etc/rand-guard/rules.d)"
systemd_dir="$(join_root /etc/systemd/system)"

run install -d -m 0755 "$bin_dir" "$lib_dir" "$config_dir" "$rules_dir" "$systemd_dir"
install_file 0755 "$user_bin" "$bin_dir/rand-guard"
install_file 0644 "$ebpf_obj" "$lib_dir/edr-ebpf"

config_dst="$config_dir/config.toml"
if [ -f "$config_dst" ]; then
  if [ "$force" -eq 1 ]; then
    backup="$config_dst.$(date -u +%Y%m%d%H%M%S).bak"
    run cp -p "$config_dst" "$backup"
    install_file 0644 "$default_config" "$config_dst"
  else
    echo "keeping existing config: $config_dst"
    echo "use --force to replace it after creating a timestamp backup"
  fi
else
  install_file 0644 "$default_config" "$config_dst"
fi

install_file 0644 "$sample_rules" "$rules_dir/sample-rules.toml"
install_file 0644 "$systemd_unit" "$systemd_dir/rand-guard.service"

cat <<EOF
rand-guard install complete.

Installed paths:
  $bin_dir/rand-guard
  $lib_dir/edr-ebpf
  $config_dst
  $rules_dir/sample-rules.toml
  $systemd_dir/rand-guard.service

Next systemd steps:
  sudo systemctl daemon-reload
  sudo systemctl enable --now rand-guard.service
  sudo journalctl -u rand-guard.service -f
EOF
