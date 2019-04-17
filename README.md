# Todo

- parse usage comment section for additional ports and protocols

This is actuall pretty easy, at least with shell scripting.

1. Find the line containing `@usage`
2. if you look at the following 4 lines, you basically capture over 99% of all usage examples.

Just look at the difference between:

grep -A 4  @usage * | grep nmap | grep "\-\-script"

and

grep -A 20  @usage * | grep nmap | grep "\-\-script"

ALL usages in the diff have at least one command captured by the `-A 4` option, so there is no need to process them.

3. grep for nmap and "--script" on the same line to identify the examples

There are a few other things to handle:

1. We may want to consider limiting multiple matches in a single script to provide just a single entry. We could use some logic for figuring out the best match. A match with a "-p" port specified is going to be better than one without. There are probably other things we can use for quality

271 matches end with one of the following:

<host/ip>
<host/s>
<host>
<hosts/networks>
<interface>
<ip>
<ips>
<port>
<ports>
<target>
<targetport>
<targets>

Notice that a few of them are port/ports/inteface, etc. We probably want to remove the ones that are host/target related at the end and just put in a space. port ones we would want to leave. But we could add the fact that it is asking for a port into the quality score. one that has a port placeholder is worse than one that provides a port number.

We will probably want to remove the ".nse" from the end of the script name.

After choosing the best possible one, we should store each in an object with the associated script name, then we could pass in a list of scripts that we want to exclude and a file containing our custom commands.

# FZF

In your `~/.zshrc`, add:

```zsh
[ -f ~/fzf-nmap.zsh ] && source ~/fzf-nmap.zsh
```

In `~/fzf-nmap.zsh`:

```zsh
# Custom zsh widgets for fzf

fzf-nmap-scripts-widget() {
  # local cmd='cat ~/.nmap-commands | egrep -v "^\s*(#|$)"'
  local cmd='nse ""'
  setopt localoptions pipefail 2> /dev/null
  local selected="$(eval "$cmd" | FZF_DEFAULT_OPTS="--height ${FZF_TMUX_HEIGHT:-40%} --preview-window=wrap:60% --preview 'nmap-fzf-parse {}' --bind ctrl-j:preview-down,ctrl-k:preview-up +m" $(__fzfcmd))"
  if [[ -z "$selected" ]]; then
    zle redisplay
    return 0
  fi
  prefix="sudo nmap -v4 -Pn -n --version-light --script"
  LBUFFER="$prefix $selected"
  zle reset-prompt
  return 0
}
zle     -N    fzf-nmap-scripts-widget
# Bind to alt+n
bindkey '\en' fzf-nmap-scripts-widget
```
