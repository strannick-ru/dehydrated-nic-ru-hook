#!/usr/bin/env bash

#
# deploy a DNS challenge on nic.ru
# Refactored to use jq and xmllint for reliability, and dig for propagation check.
#

set -e
set -u
set -o pipefail

# Check for required tools
for cmd in curl jq xmllint dig; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is required but not installed." >&2
        exit 1
    fi
done

nic_api_request() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"
    local content_type="${4:-text/xml}"
    local token="${5:-}"

    local args=("--silent" "-X" "$method")

    if [[ -n "$token" ]]; then
        args+=("-H" "Authorization: Bearer $token")
    fi

    if [[ -n "$data" ]]; then
        args+=("-d" "$data")
        args+=("-H" "Content-Type: $content_type")
    fi

    # NICRU_url is exported from config
    local response
    response=$(curl "${args[@]}" "${NICRU_url}${endpoint}")

    # Basic error check
    if echo "$response" | grep -q 'status="error"'; then
         echo "Error from NIC.RU API: $response" >&2
         return 1
    fi
    echo "$response"
}

get_token() {
    local response
    response=$(curl --silent -X POST "${NICRU_url}/oauth/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "grant_type=password" \
        --data-urlencode "username=${NICRU_user}" \
        --data-urlencode "password=${NICRU_pass}" \
        --data-urlencode "scope=(GET|PUT|POST|DELETE):/dns-master/.+" \
        --data-urlencode "client_id=${NICRU_id}" \
        --data-urlencode "client_secret=${NICRU_secret}")

    local token
    token=$(echo "$response" | jq -r '.access_token')

    if [[ "$token" == "null" || -z "$token" ]]; then
        echo "Failed to obtain access token: $response" >&2
        exit 1
    fi

    echo "$token"
}

get_zone_info() {
    local domain="$1"
    local token="$2"

    local zones_xml
    zones_xml=$(nic_api_request "GET" "/dns-master/zones" "" "" "$token")

    # Try finding the zone by stripping subdomains until we find a match
    local candidate="$domain"
    while [[ "$candidate" == *"."* ]]; do
        local service_id
        # Use xmllint to find the service-id (or service) for the zone with the candidate name
        # Using local-name() to be namespace-agnostic. NIC.RU API sometimes returns 'service' instead of 'service-id'.
        service_id=$(echo "$zones_xml" | xmllint --xpath "string(//*[local-name()='zone'][@name='$candidate']/@service | //*[local-name()='zone'][@name='$candidate']/@service-id)" - 2>/dev/null || true)

        if [[ -n "$service_id" ]]; then
            echo "$service_id $candidate"
            return 0
        fi

        # Remove leading component (e.g. sub.example.com -> example.com)
        candidate="${candidate#*.}"
    done

    echo "Zone not found for domain $domain" >&2
    echo "DEBUG: Available zones in response:" >&2
    echo "$zones_xml" | xmllint --xpath "//*[local-name()='zone']/@name" - 2>/dev/null | tr ' ' '\n' >&2 || echo "Failed to parse zones" >&2
    echo "DEBUG: First 500 chars of XML response:" >&2
    echo "${zones_xml:0:500}" >&2

    return 1
}

extract_record_ids() {
    local records_xml="$1"
    local search_name="$2"

    local record_ids

    record_ids=$(echo "$records_xml" | xmllint --xpath "//*[local-name()='rr'][(*[local-name()='name' and text()='$search_name'] or @name='$search_name') and (*[local-name()='type' and text()='TXT'] or @type='TXT')]/@id" - 2>/dev/null | grep -o 'id="[^"]*"' | cut -d'"' -f2 || true)

    if [[ -n "$record_ids" ]]; then
        printf '%s\n' "$record_ids"
        return 0
    fi

    record_ids=$(printf '%s' "$records_xml" | python3 - "$search_name" <<'PY'
import re
import sys

xml = sys.stdin.read()
search_name = sys.argv[1]
matches = []
for attrs in re.finditer(r'<rr\b([^>]*)/?>', xml):
    raw = attrs.group(1)
    attr_map = dict(re.findall(r'(\w+)="([^"]*)"', raw))
    if attr_map.get('name') == search_name and attr_map.get('type') == 'TXT' and 'id' in attr_map:
        matches.append(attr_map['id'])

for block in re.finditer(r'<rr\b([^>]*)>(.*?)</rr>', xml, re.S):
    raw_attrs = block.group(1)
    body = block.group(2)
    attr_map = dict(re.findall(r'(\w+)="([^"]*)"', raw_attrs))
    rr_id = attr_map.get('id')
    name_match = re.search(r'<name>([^<]*)</name>', body)
    type_match = re.search(r'<type>([^<]*)</type>', body)
    if rr_id and name_match and type_match and name_match.group(1) == search_name and type_match.group(1) == 'TXT':
        matches.append(rr_id)

seen = set()
for item in matches:
    if item not in seen:
        seen.add(item)
        print(item)
PY
)

    printf '%s\n' "$record_ids"
}

relative_record_name() {
    local fqdn="$1"
    local zone_name="$2"
    local normalized_fqdn="${fqdn%.}"
    local normalized_zone="${zone_name%.}"

    if [[ "$normalized_fqdn" == "$normalized_zone" ]]; then
        printf '@\n'
        return 0
    fi

    if [[ "$normalized_fqdn" == *".${normalized_zone}" ]]; then
        printf '%s\n' "${normalized_fqdn%.${normalized_zone}}" | sed 's/\.$//'
        return 0
    fi

    printf '%s\n' "$normalized_fqdn"
}

extract_txt_records() {
    local records_xml="$1"

    RECORDS_XML="$records_xml" python3 - <<'PY'
import os
import xml.etree.ElementTree as ET

xml_text = os.environ["RECORDS_XML"]
root = ET.fromstring(xml_text)

def lname(tag):
    return tag.rsplit('}', 1)[-1]

for rr in root.iter():
    if lname(rr.tag) != 'rr':
        continue
    rr_id = rr.attrib.get('id', '')
    rr_name = rr.attrib.get('name', '')
    rr_type = rr.attrib.get('type', '')
    rr_value = ''
    for child in rr:
        child_name = lname(child.tag)
        if child_name == 'name' and not rr_name:
            rr_name = (child.text or '').strip()
        elif child_name == 'type' and not rr_type:
            rr_type = (child.text or '').strip()
        elif child_name == 'txt':
            for txt_child in child:
                if lname(txt_child.tag) == 'string':
                    rr_value = (txt_child.text or '').strip()
                    break
    if rr_type == 'TXT' and rr_id and rr_name:
        print(f"{rr_id}\t{rr_name}\t{rr_value}")
PY
}

build_txt_rr_xml() {
    local fqdn="$1"
    local ttl="$2"
    shift 2

    local token_value
    cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<request>
    <rr-list>
EOF
    for token_value in "$@"; do
        cat <<EOF
        <rr>
            <name>${fqdn}</name>
            <ttl>${ttl}</ttl>
            <type>TXT</type>
            <txt>
                <string>${token_value}</string>
            </txt>
        </rr>
EOF
    done
    cat <<EOF
    </rr-list>
</request>
EOF
}

wait_for_propagation() {
    local FQDN="$1"
    local ZONE_NAME="$2"
    shift 2
    local EXPECTED_TOKENS=("$@")
    local NS_DISCOVERY_RESOLVER="${NICRU_ns_resolver:-77.88.8.8}"
    local PUBLIC_RESOLVERS="${NICRU_public_resolvers:-1.1.1.1 8.8.8.8}"
    local AUTHORITATIVE_TIMEOUT="${NICRU_authoritative_timeout:-300}"
    local PUBLIC_TIMEOUT="${NICRU_public_timeout:-1800}"

    echo "Resolving authoritative nameservers for $ZONE_NAME via $NS_DISCOVERY_RESOLVER..."
    # Get NS records, clean up output
    local NS_LIST
    NS_LIST=$(dig @"$NS_DISCOVERY_RESOLVER" +short NS "$ZONE_NAME")

    if [[ -z "$NS_LIST" ]]; then
        echo "Warning: Public resolver $NS_DISCOVERY_RESOLVER returned no NS records for $ZONE_NAME. Falling back to local resolver."
        NS_LIST=$(dig +short NS "$ZONE_NAME")
    fi

    if [[ -z "$NS_LIST" ]]; then
        echo "Warning: Could not determine authoritative nameservers for $ZONE_NAME. Falling back to sleep."
        local secs=60
        while [ $secs -gt 0 ]; do
            echo -ne "Waiting $secs seconds...\r"
            sleep 1
            : $((secs--))
        done
        echo ""
        return
    fi

    local NS_ARRAY=()
    local NS
    while IFS= read -r NS; do
        [[ -n "$NS" ]] || continue
        NS_ARRAY+=("${NS%.}")
    done <<< "$NS_LIST"

    echo "Waiting for propagation on authoritative servers: ${NS_ARRAY[*]}"
    local START_TIME=$(date +%s)

    while true; do
        local CURRENT_TIME=$(date +%s)
        local ELAPSED=$((CURRENT_TIME - START_TIME))

        if [[ $ELAPSED -ge $AUTHORITATIVE_TIMEOUT ]]; then
            echo "Timeout waiting for authoritative propagation ($AUTHORITATIVE_TIMEOUT seconds). Proceeding anyway."
            break
        fi

        for NS in "${NS_ARRAY[@]}"; do
            local RECORDS ALL_FOUND TOKEN_VALUE
            RECORDS=$(dig +short @"$NS" TXT "$FQDN" | tr -d '"')
            ALL_FOUND=1
            for TOKEN_VALUE in "${EXPECTED_TOKENS[@]}"; do
                if ! printf '%s\n' "$RECORDS" | grep -Fxq -- "$TOKEN_VALUE"; then
                    ALL_FOUND=0
                    break
                fi
            done

            if [[ "$ALL_FOUND" -eq 1 ]]; then
                echo "Authoritative propagation confirmed on $NS."
                break 2
            fi
        done

        echo -ne "Waiting for authoritative DNS propagation... ($ELAPSED/${AUTHORITATIVE_TIMEOUT}s)\r"
        sleep 5
    done

    echo ""
    echo "Waiting for public DNS propagation via: $PUBLIC_RESOLVERS"

    START_TIME=$(date +%s)
    while true; do
        local CURRENT_TIME=$(date +%s)
        local ELAPSED=$((CURRENT_TIME - START_TIME))

        if [[ $ELAPSED -ge $PUBLIC_TIMEOUT ]]; then
            echo "Timeout waiting for public DNS propagation ($PUBLIC_TIMEOUT seconds). Proceeding anyway."
            break
        fi

        local RESOLVER
        local ALL_RESOLVERS_READY=1
        for RESOLVER in $PUBLIC_RESOLVERS; do
            local RECORDS ALL_FOUND TOKEN_VALUE
            RECORDS=$(dig +short @"$RESOLVER" TXT "$FQDN" | tr -d '"')
            ALL_FOUND=1
            for TOKEN_VALUE in "${EXPECTED_TOKENS[@]}"; do
                if ! printf '%s\n' "$RECORDS" | grep -Fxq -- "$TOKEN_VALUE"; then
                    ALL_FOUND=0
                    break
                fi
            done

            if [[ "$ALL_FOUND" -ne 1 ]]; then
                ALL_RESOLVERS_READY=0
                break
            fi
        done

        if [[ "$ALL_RESOLVERS_READY" -eq 1 ]]; then
            echo "Public DNS propagation confirmed via all resolvers."
            return 0
        fi

        echo -ne "Waiting for public DNS propagation... ($ELAPSED/${PUBLIC_TIMEOUT}s)\r"
        sleep 5
    done

    echo ""
}

deploy_challenge() {
    local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"
    local SUBDOMAIN="_acme-challenge"
    local FQDN="${SUBDOMAIN}.${DOMAIN}."
    local TTL="60"

    echo "deploy_challenge called: ${DOMAIN}"

    local TOKEN
    TOKEN=$(get_token)

    # Get Zone Info
    local ZONE_INFO
    ZONE_INFO=$(get_zone_info "$DOMAIN" "$TOKEN")
    read -r SERVICE_ID ZONE_NAME <<< "$ZONE_INFO"
    local RELATIVE_NAME
    RELATIVE_NAME=$(relative_record_name "$FQDN" "$ZONE_NAME")

    echo "Found Zone: $ZONE_NAME (Service ID: $SERVICE_ID)"

    local RECORDS_XML
    RECORDS_XML=$(nic_api_request "GET" "/dns-master/services/$SERVICE_ID/zones/$ZONE_NAME/records" "" "" "$TOKEN")

    local EXISTING_TOKENS=()
    local TOKEN_ALREADY_PRESENT=0
    local record_line record_id record_name record_value
    while IFS=$'\t' read -r record_id record_name record_value; do
        [[ -n "$record_id" ]] || continue
        if [[ "$record_name" == "$FQDN" || "$record_name" == "$RELATIVE_NAME" ]]; then
            EXISTING_TOKENS+=("$record_value")
            if [[ "$record_value" == "$TOKEN_VALUE" ]]; then
                TOKEN_ALREADY_PRESENT=1
            fi
        fi
    done < <(extract_txt_records "$RECORDS_XML")

    if [[ "$TOKEN_ALREADY_PRESENT" -eq 1 ]]; then
        echo "Token already present for ${FQDN}."
    else
        local XML_DATA
        XML_DATA=$(build_txt_rr_xml "$FQDN" "$TTL" "$TOKEN_VALUE")

        echo "Adding record ${FQDN}..."
        nic_api_request "PUT" "/dns-master/services/$SERVICE_ID/zones/$ZONE_NAME/records" "$XML_DATA" "text/xml" "$TOKEN" > /dev/null

        echo "Committing changes..."
        nic_api_request "POST" "/dns-master/services/$SERVICE_ID/zones/$ZONE_NAME/commit" "" "" "$TOKEN" > /dev/null

        EXISTING_TOKENS+=("$TOKEN_VALUE")
    fi

    # Wait for propagation
    wait_for_propagation "${FQDN}" "${ZONE_NAME}" "${EXISTING_TOKENS[@]}"
}

clean_challenge() {
    local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"
    local SUBDOMAIN="_acme-challenge"

    echo "clean_challenge called: ${DOMAIN}"

    local TOKEN
    TOKEN=$(get_token)

    local ZONE_INFO
    ZONE_INFO=$(get_zone_info "$DOMAIN" "$TOKEN")
    read -r SERVICE_ID ZONE_NAME <<< "$ZONE_INFO"

    local RECORDS_XML
    RECORDS_XML=$(nic_api_request "GET" "/dns-master/services/$SERVICE_ID/zones/$ZONE_NAME/records" "" "" "$TOKEN")

    local SEARCH_NAME="${SUBDOMAIN}.${DOMAIN}."
    local RELATIVE_NAME
    RELATIVE_NAME=$(relative_record_name "$SEARCH_NAME" "$ZONE_NAME")
    local RECORD_IDS
    local record_line record_id record_name record_value

    while IFS=$'\t' read -r record_id record_name record_value; do
        [[ -n "$record_id" ]] || continue
        if [[ "$record_name" == "$SEARCH_NAME" || "$record_name" == "$RELATIVE_NAME" ]]; then
            if [[ -z "$TOKEN_VALUE" || "$TOKEN_VALUE" == "ignored" || "$record_value" == "$TOKEN_VALUE" ]]; then
                RECORD_IDS+="$record_id "$'\n'
            fi
        fi
    done < <(extract_txt_records "$RECORDS_XML")

    RECORD_IDS=$(printf '%s' "$RECORD_IDS" | tr ' ' '\n' | sed '/^$/d' || true)

    if [[ -z "$RECORD_IDS" ]]; then
        echo "No records found to clean."
        return 0
    fi

    for RID in $RECORD_IDS; do
        echo "Deleting record ID: $RID"
        nic_api_request "DELETE" "/dns-master/services/$SERVICE_ID/zones/$ZONE_NAME/records/$RID" "" "" "$TOKEN" > /dev/null
    done

    echo "Committing changes..."
    nic_api_request "POST" "/dns-master/services/$SERVICE_ID/zones/$ZONE_NAME/commit" "" "" "$TOKEN" > /dev/null
}

invalid_challenge() {
    local DOMAIN="${1}" RESPONSE="${2}"
    echo "invalid_challenge called: ${DOMAIN}, ${RESPONSE}"
}

deploy_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}"
    echo "deploy_cert called: ${DOMAIN}"
}

unchanged_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}"
    echo "unchanged_cert called: ${DOMAIN}"
}

exit_hook() {
  :
}

startup_hook() {
  :
}

HANDLER=$1; shift;
if [ -n "$(type -t $HANDLER)" ] && [ "$(type -t $HANDLER)" = function ]; then
  $HANDLER "$@"
fi
