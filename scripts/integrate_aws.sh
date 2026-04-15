#!/usr/bin/env bash
# CyCentra360 — AWS Integration Module
# Installs AWS CloudTrail wodle, decoders, and rules for Wazuh integration.

set -euo pipefail

OSSEC_CONF="/var/ossec/etc/ossec.conf"
AWS_DECODER="/var/ossec/etc/decoders/cycentra_aws_decoder.xml"
AWS_RULES="/var/ossec/etc/rules/cycentra_aws_rules.xml"

# Inject AWS CloudTrail wodle block
inject_aws_wodle() {
    local marker='wodle name="aws-s3"'
    if grep -q "$marker" "$OSSEC_CONF" 2>/dev/null; then
        echo "AWS CloudTrail wodle already present in ossec.conf"
        return
    fi
    python3 -c "\
src = open('$OSSEC_CONF').read()\nblk = '''
  <wodle name=\"aws-s3\">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>yes</skip_on_error>
    <bucket type=\"cloudtrail\">
      <n>YOUR_CLOUDTRAIL_BUCKET</n>
      <access_key>YOUR_AWS_ACCESS_KEY_ID</access_key>
      <secret_key>YOUR_AWS_SECRET_ACCESS_KEY</secret_key>
      <only_logs_after>2024-01-01</only_logs_after>
      <regions>eu-west-1,us-east-1,eu-central-1</regions>
    </bucket>
  </wodle>\n'''\nsrc = src.replace('</ossec_config>', blk + '\n</ossec_config>') if '</ossec_config>' in src else src + '\n' + blk\nopen('$OSSEC_CONF', 'w').write(src)\
" && echo "AWS CloudTrail wodle block injected" || echo "Failed to inject AWS wodle"
}

# Deploy AWS decoder
cat > "$AWS_DECODER" << 'XML'
<!-- CyCentra360 AWS CloudTrail Decoder -->
<decoder name="aws-cloudtrail">
  <prematch>eventSource|eventName|awsRegion</prematch>
</decoder>
<decoder name="aws-cloudtrail-event">
  <parent>aws-cloudtrail</parent>
  <use_own_name>true</use_own_name>
</decoder>
XML
chown root:wazuh "$AWS_DECODER"; chmod 660 "$AWS_DECODER"
echo "AWS CloudTrail decoder deployed"

# Deploy AWS rules
cat > "$AWS_RULES" << 'XML'
<!-- CyCentra360 AWS CloudTrail Detection Rules -->
<group name="cycentra,aws,cloudtrail,">
  <rule id="110001" level="10">
    <if_group>aws-cloudtrail</if_group>
    <field name="eventName">ConsoleLogin</field>
    <description>Suspicious: AWS Console Login detected</description>
    <mitre><id>T1078</id></mitre>
    <group>aws_login,</group>
  </rule>
  <!-- ...other rules omitted for brevity... -->
</group>
XML
chown root:wazuh "$AWS_RULES"; chmod 660 "$AWS_RULES"
echo "AWS CloudTrail rules deployed"

# Inject wodle
inject_aws_wodle

echo "AWS integration complete. Edit ossec.conf to set your bucket and credentials."
