#!/bin/bash
## change to "bin/sh" when necessary

auth_email=""                                       # The email used to login 'https://dash.cloudflare.com'
auth_method="token"                                 # Set to "global" for Global API Key or "token" for Scoped API Token
auth_key=""                                         # Your API Token or Global API Key
zone_identifier=""                                  # Can be found in the "Overview" tab of your domain
record_name=""                                      # Which record you want to be synced
ttl="3600"                                          # Set the DNS TTL (seconds)
proxy="false"                                       # Set the proxy to true or false
sitename=""                                         # Title of site "Example Site"
slackchannel=""                                     # Slack Channel #example
slackuri=""                                         # URI for Slack WebHook "https://hooks.slack.com/services/xxxxx"
discorduri=""                                       # URI for Discord WebHook "https://discordapp.com/api/webhooks/xxxxx"


###########################################
# Commands
###########################################
Help()
{
    echo "Cloudflare DDNS Updater by K0p1-Git."
    echo "Repo link : https://github.com/K0p1-Git/cloudflare-ddns-updater"
    echo
    echo "Usage: [-h|-d|-f]"
    echo "Description:"
    echo "-h    Print this help page."
    echo "-d    Enable debug mode."
    echo "-f    Ignore unchanged IP detection."
}

options=$(getopt -l "help,debug,force" -o "hdf" -a -- "$@")
eval set -- "$options"

while true; do
    case $1 in
        -h|--help)
            Help
            exit 0;;
        -d|--debug)
            debug=true
            logger -s "DDNS Updater: Debug mode is ON";;
        -f|--force)
            bypass=true
            logger -s "DDNS Updater: IP check bypass is ON";;
        --)
            shift
            break;;
    esac
    shift
done

###########################################
## Debug logger (to increase readability)
###########################################
bugger(){
    msg=$1

    if [ "${debug}" = true ]; then
        logger -s "DDNS Updater: ${msg}"
    fi
}

###########################################
## Check if we have a public IP
###########################################
ipv4_regex='([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])'
ip=$(curl -s -4 https://cloudflare.com/cdn-cgi/trace | grep -E '^ip'); ret=$?
if [[ ! $ret == 0 ]]; then # In the case that cloudflare failed to return an ip.
    # Attempt to get the ip from other websites.
    ip=$(curl -s https://api.ipify.org || curl -s https://ipv4.icanhazip.com)
    bugger "Using IP from alternative websites..."
else
    # Extract just the ip from the ip line from cloudflare.
    ip=$(echo $ip | sed -E "s/^ip=($ipv4_regex)$/\1/")
    bugger "Using IP from Cloudflare..."
fi

# Use regex to check for proper IPv4 format.
if [[ ! $ip =~ ^$ipv4_regex$ ]]; then
    logger -s "DDNS Updater: Failed to find a valid IP."
    bugger "Response - ${ip}"
    exit 2
fi

bugger "Your IP is ${ip}"

###########################################
## Check and set the proper auth header
###########################################
if [[ "${auth_method}" == "global" ]]; then
  auth_header="X-Auth-Key:"
  bugger "Authentication method is set as 'global'."
else
  auth_header="Authorization: Bearer"
  bugger "Authentication method is set as 'token'."
fi

###########################################
## Seek for the A record
###########################################
error_codes=("400" "401" "402" "403" "404" "405" "406" "429" "500")

logger -s "DDNS Updater: Check Initiated"
record=$(curl --write-out "%{http_code}" -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records?type=A&name=$record_name" \
                      -H "X-Auth-Email: $auth_email" \
                      -H "$auth_header $auth_key" \
                      -H "Content-Type: application/json")

status=$(echo $record | tail -c 4)

bugger "Record check response - ${record::-4}"

if [[ " ${error_codes[*]} " =~ " ${status} " ]]; then
  logger -s "DDNS Updater: Error while checking record identifier!"
  exit 1
fi

bugger "Record check request completed without errors."

###########################################
## Check if the domain has an A record
###########################################
if [[ $record == *"\"count\":0"* ]]; then
  logger -s "DDNS Updater: Record does not exist, perhaps create one first? (${ip} for ${record_name})"
  exit 1
fi

###########################################
## Get existing IP
###########################################
# Compare if they're the same
old_ip=$(echo "$record" | sed -E 's/.*"content":"(([0-9]{1,3}\.){3}[0-9]{1,3})".*/\1/')
bugger "Domain record (${record_name}) is holding IP (${old_ip})."

if [ "${bypass}" = true ]; then
  logger -s "DDNS Updater: Bypassing IP checks..."
else
  if [[ $ip == $old_ip ]]; then
    logger -s "DDNS Updater: IP ($ip) for ${record_name} has not changed."
    exit 0
  fi
fi

###########################################
## Set the record identifier from result
###########################################
record_identifier=$(echo "$record" | sed -E 's/.*"id":"(\w+)".*/\1/')

bugger "Record identifier is \"${record_identifier}\"."

###########################################
## Change the IP@Cloudflare using the API
###########################################
update=$(curl --write-out "%{http_code}" -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records/$record_identifier" \
                     -H "X-Auth-Email: $auth_email" \
                     -H "$auth_header $auth_key" \
                     -H "Content-Type: application/json" \
                     --data "{\"type\":\"A\",\"name\":\"$record_name\",\"content\":\"$ip\",\"ttl\":\"$ttl\",\"proxied\":${proxy}}")

status=$(echo $update | tail -c 4)

bugger "Domain update response - ${update::-4}"
####################
## Update Failed
####################
if [[ " ${error_codes[*]} " =~ " ${status} " ]] || [[ " ${update} " =~ "\"success\":false" ]]; then
  logger -s "DDNS Updater: Error while completing update API request!"

  ### Slack
  if [[ $slackuri != "" ]]; then
    curl -L -X POST $slackuri \
    --data-raw '{
      "channel": "'$slackchannel'",
      "text" : "'"$sitename"' DDNS Update Failed: '$record_name': '$record_identifier' ('$ip')."
    }'
  fi
  ### Discord
  if [[ $discorduri != "" ]]; then
    curl -i -H "Accept: application/json" -H "Content-Type:application/json" -X POST \
    --data-raw '{
      "content" : "'"$sitename"' DDNS Update Failed: '$record_name': '$record_identifier' ('$ip')."
    }' $discorduri
  fi

  logger -s "DDNS Updater: Failed to update IP ($ip) for $record_name."
  exit 1
####################
## Update Success
####################
else
  bugger "Domain IP update request completed without errors."
  
  ### Slack
  if [[ $slackuri != "" ]]; then
    curl -L -X POST $slackuri \
    --data-raw '{
      "channel": "'$slackchannel'",
      "text" : "'"$sitename"' Updated: '$record_name''"'"'s'""' new IP Address is '$ip'"
    }'
  fi
  ### Discord
  if [[ $discorduri != "" ]]; then
    curl -i -H "Accept: application/json" -H "Content-Type:application/json" -X POST \
    --data-raw '{
      "content" : "'"$sitename"' Updated: '$record_name''"'"'s'""' new IP Address is '$ip'"
    }' $discorduri
  fi

  logger -s "DDNS Updater: $ip $record_name DDNS updated."
  exit 0
fi
