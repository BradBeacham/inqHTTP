# inqHTTP
<pre>
    _             __  __________________         __  
   (_)___  ____ _/ / / /_  __/_  __/ __ \  _____/ /_ 
  / / __ \/ __ `/ /_/ / / /   / / / /_/ / / ___/ __ \
 / / / / / /_/ / __  / / /   / / / ____/ / /  / /_/ /
/_/_/ /_/\__, /_/ /_/ /_/   /_/ /_/   (_)_/  /_.___/ 
           /_/                                                                                       
</pre>

Overview
--------

Inquest is a script current in development which is intended to act as a wrapper for various other tools included within Kali Linux.  It will streamline the enumeration process helping you on your way to popping mad shellz.

This sub script (inqHTTP.rb) will eventually find its way into the primary inquest.rb script.  This allows for the standardises enumeration of web services with Nikto and Wfuzz.  Default option will run them both in parallel against the assocaited targed, but either may be ran.  Wfuzz has default configured options with 11 wordlists.  These are currently hardcoded, and as such will need to be updated for your install.  This will eventually be changed to a proper configuration file.

ISSUE: WFuzz is currently limited to fuzzing HTTP sites, and throws errors when fuzzing HTTPS.  This will be something I need to look into eventually for a proper alternative.

Basic threading is implemented to run scans for each host in parallel, and the entire function is wrapped so multiple hosts (upto 10 currently), may be scanned at any one given time.  Increasing the threads > 2 is not really reccomended for any hosts accessed over the internet or via a VPN.

Installation
------------

    apt-get install nikto
    apt-get install wfuzz
    https://github.com/BradBeacham/inqHTTP.git
    gem install highline -v 1.7.8
    Update Wfuzz wordlists as appropriate (Lines 228-240)

Usage
-----

    Usage: inqHTTP.rb
        -d, --output-dir <FILE>          Specify the directory to save all output
        -i <HOST>                        Specify individual host to perform enumeration against
        -l, --input-list <FILE>          File containing one host per line to read from (NO SUBNETS!!!!)
            --threads [1-10]             Specify the number of concurrent scans to perform
        -t [ fuzz | nikto ]              Perform individual function, rather than both
            --no-colour                  Removes colourisation from the ourput
        -h, --help                       Display this screen

