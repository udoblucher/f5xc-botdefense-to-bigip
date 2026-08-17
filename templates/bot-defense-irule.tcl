# Bot Defense entrypoint iRule -- template for manual configuration.
# Same rule xcbot.py generates, with the default object names.
#
# Requires, on the same virtual server: an HTTP profile, an HTML profile whose
# rule appends the Bot Defense script tag, and the LTM policy that steers
# protected paths to the Bot Defense pool.
#
# Requires a string data group named below, holding one record per entrypoint
# path (key: path, value: methods). Name it as the virtual server's partition
# sees it -- bare in /Common, /partition/name otherwise.
#
# This rule does NOT steer traffic -- the LTM policy bot-defense-policy does that.
# Its job is to keep the HTML parser off every response that does not need it:
# the HTML profile is disabled by default and enabled only for responses to a
# request whose path is listed in the bot-defense-entrypoint data group.
when RULE_INIT {
    # 1 = log every request decision to /var/log/ltm, 0 = silent.
    # Leave at 1 while validating, then set to 0 and reload the rule.
    set static::botdefense_debug 1
    # Entrypoint paths + their methods, matched with `contains`. XC does not
    # say which pages need the script, so this data group is maintained by
    # hand: add a record per page, and drop the "/" catch-all once you have.
    # Changing the injection scope means editing the data group, not this rule.
    set static::botdefense_entrypoints "bot-defense-entrypoint"
}

when HTTP_REQUEST priority 500 {
    set xc_decorate 0
    set xc_path [string tolower [HTTP::path -normalized]]
    set xc_method [HTTP::method]

    if { [class match -value -- $xc_path contains $static::botdefense_entrypoints] contains $xc_method } {
        set xc_decorate 1
        if { $static::botdefense_debug } {
            log local0. "Bot Defense Entrypoint -- Client: [IP::client_addr] URI: [HTTP::uri]"
        }
    } else {
        if { $static::botdefense_debug } {
            log local0. "Request: $xc_method [HTTP::uri] is NOT an Entrypoint"
        }
    }
}

when SERVER_CONNECTED priority 500 {
    # SSL offload: the app pool may be cleartext even though the bot pool is 443.
    if { [LB::server port] != 443 } {
        SSL::disable
    }
}

when HTTP_RESPONSE priority 500 {
    HTML::disable
    if { $xc_decorate } {
        if { $static::botdefense_debug } {
            log local0. "Decorate Response -- Enabling HTML Content Profile. Path: $xc_path"
        }
        HTML::enable
    }
}
