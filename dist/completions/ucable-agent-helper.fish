# SPDX-License-Identifier: GPL-3.0-or-later
# fish completion for ucable-agent-helper
complete -c ucable-agent-helper -l select -d 'Device-selection window'
complete -c ucable-agent-helper -l timeout -r -d 'Close after SECS seconds'
complete -c ucable-agent-helper -l request-type -r -a 'mc ga' -d 'Request type'
complete -c ucable-agent-helper -s h -l help -d 'Print help'
complete -c ucable-agent-helper -s V -l version -d 'Print version'
