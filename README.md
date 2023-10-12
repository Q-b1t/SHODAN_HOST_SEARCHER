# SHODAN HOST SEARCHER
This script receives as argument a list of hosts, queries the shodan API for information on such hosts, and returns a series of tables based on the information found on the hosts.
## Setup
In order to use the script, one needs access to the [Shodan CLI](https://cli.shodan.io/). The easiest way is to have an account with membership.
Once the API key is retrieved, it must be set inside the configuration file (```shodan_conf.cfg```).
### Example
```
[API_KEY]
shodan = edd23kjr34wefk34rj3nwf3kjf4
```