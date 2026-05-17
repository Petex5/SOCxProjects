# Lab 3 - Task 3: Custom Parsing Rules

## Overview
This document contains custom decoder and rule definitions for the Wazuh SIEM platform. Custom parsing rules enable the SIEM to properly interpret and categorize log data from various sources, allowing for accurate threat detection and alerting.

## 3.1 Custom Decoders

### 3.1.1 Firewall Decoder (pfSense/OPNsense)
```xml
<decoder name="pfsense-firewall">
  <prematch>^filterlog</prematch>
</decoder>

<decoder name="pfsense-firewall-extended">
  <parent>pfsense-firewall</parent>
  <regex>^(\d+),(\d+),(.*?),(\d+),(\w+),(\d+),(.*?),(.*?),(\d+\.</ regex>
  <order>rule_number,sub_rule_number,interface,reason,action,direction,ip_protocol,source_ip,destination_ip</order>
</decoder>
```

### 3.1.2 Windows Authentication Decoder
```xml
<decoder name="windows-auth">
  <prematch>^Microsoft-Windows-Security-Auditing</prematch>
</decoder>

<decoder name="windows-auth-extended">
  <parent>windows-auth</parent>
  <regex>Event ID (\d+).*Account Name: (\S+).*Source Network Address: (\d+\.</regex>
  <order>event_id,username,source_ip</order>
</decoder>
```

### 3.1.3 Web Server Access Log Decoder (Nginx)
```xml
<decoder name="nginx-access">
  <prematch>^\d+\.</prematch>
</decoder>

<decoder name="nginx-access-extended">
  <parent>nginx-access</parent>
  <regex>^(\d+\.[0-9.]+).*\[([^]]+)\] "(\w+) (\S+) (HTTP/[\d.]+)" (\d+) (\d+)</regex>
  <order>srcip,timestamp,action,url,protocol,status_code,response_size</order>
</decoder>
```

### 3.1.4 Custom Application JSON Decoder
```xml
<decoder name="json-app-logs">
  <program_name>custom-app</program_name>
  <json>
    <field name="log_level">level</field>
    <field name="user_id">user_id</field>
    <field name="action">action</field>
    <field name="source_ip">ip_address</field>
    <field name="message">msg</field>
  </json>
</decoder>
```

## 3.2 Custom Rules

### 3.2.1 Firewall Rules
```xml
<!-- Rule 100101: Firewall blocked connection attempt -->
<group name="firewall,pfsense,">
  <rule id="100101" level="5">
    <if_sid>100100</if_sid>
    <match>action=deny</match>
    <description>Firewall blocked connection attempt from $srcip to $dstip</description>
  </rule>

  <!-- Rule 100102: Multiple blocked attempts (potential scan) -->
  <rule id="100102" level="10">
    <if_sid>100101</if_sid>
    <frequency>10</frequency>
    <timeframe>60</timeframe>
    <same_field>srcip</same_field>
    <description>Possible port scan detected - multiple blocked connections from $srcip</description>
    <group>scan,</group>
  </rule>
</group>
```

### 3.2.2 Authentication Failure Rules
```xml
<!-- Rule 100201: Single authentication failure -->
<group name="authentication,windows,">
  <rule id="100201" level="5">
    <event_id>4625</event_id>
    <description>Windows authentication failure for user $username from $srcip</description>
    <group>authentication_failed,</group>
  </rule>

  <!-- Rule 100202: Brute force detection -->
  <rule id="100202" level="12">
    <if_sid>100201</if_sid>
    <frequency>5</frequency>
    <timeframe>120</timeframe>
    <same_field>username</same_field>
    <description>Possible brute force attack detected - multiple auth failures for $username</description>
    <group>brute_force,authentication_failed,</group>
  </rule>

  <!-- Rule 100203: Successful login after failures -->
  <rule id="100203" level="10">
    <event_id>4624</event_id>
    <check_if_sid>100201</check_if_sid>
    <timeframe>300</timeframe>
    <same_field>username</same_field>
    <description>Successful login after multiple failed attempts for $username - potential compromise</description>
    <group>authentication_success,investigate,</group>
  </rule>
</group>
```

### 3.2.3 Web Attack Detection Rules
```xml
<group name="web,nginx,attack,">
  <!-- SQL Injection attempt -->
  <rule id="100301" level="10">
    <decoder>nginx-access-extended</decoder>
    <match>UNION|SELECT|INSERT|DROP|DELETE|UPDATE|--|\bOR\b.*=</match>
    <description>Possible SQL injection attempt in URL from $srcip</description>
    <group>sqli,web_attack,</group>
  </rule>

  <!-- Path traversal attempt -->
  <rule id="100302" level="10">
    <decoder>nginx-access-extended</decoder>
    <match>\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f</match>
    <description>Possible path traversal attempt from $srcip</description>
    <group>path_traversal,web_attack,</group>
  </rule>

  <!-- XSS attempt -->
  <rule id="100303" level="10">
    <decoder>nginx-access-extended</decoder>
    <match>&lt;script|javascript:|onerror=|onload=|%3cscript</match>
    <description>Possible XSS attempt from $srcip</description>
    <group>xss,web_attack,</group>
  </rule>

  <!-- HTTP 500 errors (application error) -->
  <rule id="100304" level="7">
    <decoder>nginx-access-extended</decoder>
    <match>HTTP/[\d.]+" 500</match>
    <description>Web server returned HTTP 500 error - possible application issue or attack</description>
  </rule>
</group>
```

### 3.2.4 Privilege Escalation Rules
```xml
<group name="privilege,linux,">
  <!-- Sudo command execution -->
  <rule id="100401" level="7">
    <match>sudo:</match>
    <regex>COMMAND=(\S+)</regex>
    <description>Sudo command executed: $1 by user on $(hostname)</description>
  </rule>

  <!-- SUID binary execution -->
  <rule id="100402" level="10">
    <match>exe="\/tmp\/|\/dev\/shm\/|\/var\/tmp\/(</match>
    <description>Potentially malicious SUID execution from temp directory</description>
    <group>malware,privilege_escalation,</group>
  </rule>
</group>
```

## 3.3 Field Extraction and Enrichment

### 3.3.1 GeoIP Enrichment
Configure GeoIP lookup for source IPs using MaxMind database:
```xml
<ossec_config>
  <ruleset>
    <rule_dir>rules</rule_dir>
    <rule_exclude>0299-info.xml</rule_exclude>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <decoder_exclude>syscat_decoder.xml</decoder_exclude>
    <list>etc/lists/geoip-data</list>
    <info_type>M</info_type>
  </ruleset>
</ossec_config>
```

### 3.3.2 CDB Lists for IOC Matching
```xml
# Create file: /var/ossec/etc/lists/blacklist-ips
192.168.1.100:Malicious-ACTOR-1
10.0.0.50:Known-C2-Server
```

```xml
<group name="threat-intel,">
  <rule id="100501" level="15">
    <if_matched_group>firewall,web</if_matched_group>
    <list field="srcip" lookup="match_key">etc/lists/blacklist-ips</list>
    <description>Alert - Traffic from known malicious IP $srcip matched CDB list</description>
    <group>threat_intel,malicious_ip,</group>
  </rule>
</group>
```

## 3.4 Rule Testing and Validation

### 3.4.1 Test Decoders with wazuh-logtest
```
/var/ossec/bin/wazuh-logtest
> 2024-01-15T10:23:45 firewall01 filterlog: 5,e,em0,match,deny,in,4,0x0,,65,,0,0,none,6,tcp,17,192.168.1.100,8.8.8.8,45123,53,0,S
```

### 3.4.2 Test Rules
```
/var/ossec/bin/wazuh-logtest
> Testing rule 100201
> Event log: Microsoft-Windows-Security-Auditing Event ID 4625
```

## 3.5 Maintenance and Updates

- Review and update rules monthly
- Add new decoders for newly deployed log sources
- Tune rule levels based on false positive analysis
- Document all custom rules in this file
- Version control all decoder/rule changes

## References
- Wazuh Decoder Guide: https://documentation.wazuh.com/current/user-manual/ruleset/custom/rules.html
- Wazuh Rule Guide: https://documentation.wazuh.com/current/user-manual/ruleset/custom/decoders.html
- MITRE ATT&CK Mapping: https://attack.mitre.org/
