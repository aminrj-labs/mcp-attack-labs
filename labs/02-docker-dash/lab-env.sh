#!/usr/bin/env zsh
# Source this file to switch Docker context to Docker Desktop for this lab.
# Usage:
#   source lab-env.sh          # enter lab mode
#   source lab-env.sh --off    # restore Rancher Desktop

if [[ "${1}" == "--off" ]]; then
  export DOCKER_HOST="unix:///Users/ARAJI/.rd/docker.sock"
  docker context use default
  echo "✓ Switched back to Rancher Desktop (default)"
else
  unset DOCKER_HOST
  docker context use desktop-linux
  echo "✓ Switched to Docker Desktop for this lab session"
  echo "  Run 'source lab-env.sh --off' to restore Rancher Desktop"
fi
