# SPDX-License-Identifier: GPL-3.0-or-later
# bash completion for ucable-agent-helper
_ucable_agent_helper() {
    local cur
    cur=${COMP_WORDS[COMP_CWORD]}
    COMPREPLY=($(compgen -W \
        '--select --timeout --request-type -h --help -V --version' \
        -- "$cur"))
}
complete -F _ucable_agent_helper ucable-agent-helper
