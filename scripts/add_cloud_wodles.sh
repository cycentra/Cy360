#!/usr/bin/env bash
# CyCentra360 — Cloud Wodle Integration Module
# Injects AWS, Azure, O365 wodle blocks into ossec.conf as needed.

set -euo pipefail

OSSEC_CONF="/var/ossec/etc/ossec.conf"

inject_wodle() {
    local marker="$1" label="$2" block="$3"
    if grep -q "$marker" "$OSSEC_CONF" 2>/dev/null; then
        echo "$label wodle already in ossec.conf"
        return
    fi
    python3 -c "\
src = open('$OSSEC_CONF').read()\nblk = '''$block'''\nsrc = src.replace('</ossec_config>', blk + '\n</ossec_config>') if '</ossec_config>' in src else src + '\n' + blk\nopen('$OSSEC_CONF', 'w').write(src)\
" && echo "$label wodle stub added to ossec.conf" || echo "$label wodle inject failed"
}

# Example: AWS CloudTrail (user should edit placeholders after injection)
inject_wodle 'wodle name="aws-s3"' "AWS CloudTrail" \
'
  <wodle name="aws-s3">
    <disabled>yes</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>yes</skip_on_error>
    <bucket type="cloudtrail">
      <n>PLACEHOLDER_CLOUDTRAIL_BUCKET</n>
      <access_key>PLACEHOLDER_AWS_ACCESS_KEY_ID</access_key>
      <secret_key>PLACEHOLDER_AWS_SECRET_ACCESS_KEY</secret_key>
      <only_logs_after>2024-01-01</only_logs_after>
      <regions>eu-west-1,us-east-1,eu-central-1</regions>
    </bucket>
  </wodle>'

# Add similar blocks for Azure, O365 as needed
