# Lab 6: Build a Home SOC Lab

## Overview

This lab guides you through building a complete home Security Operations Center (SOC) lab environment. You will set up virtual machines, configure network segmentation, deploy a SIEM (Wazuh), integrate log sources, and create detection rules. This lab provides hands-on experience building a functional SOC environment that mirrors enterprise security operations.

## Objectives

- Build a virtualised home lab environment using VirtualBox or VMware
- Deploy a SIEM platform (Wazuh) on a dedicated Linux VM
- Configure network segmentation (management, production, and DMZ networks)
- Forward logs from Windows and Linux endpoints to the SIEM
- Create custom detection rules for common attack scenarios
- Build a SOC analyst dashboard with meaningful visualisations
- Document the entire architecture and configuration

## Tasks

1. **Plan the Lab Architecture**
   - Define the network topology (SIEM server, Windows endpoint, Linux endpoint)
   - Plan IP addressing and network segments
   - Document hardware requirements (minimum 16GB RAM, 50GB storage)

2. **Set Up Hypervisor**
   - Install VirtualBox or VMware Workstation Player
   - Create host-only and NAT network adapters
   - Configure network segmentation (internal networks for lab isolation)

3. **Deploy the SIEM (Wazuh)**
   - Download and install Wazuh all-in-one on Ubuntu Server
   - Configure the Wazuh manager and indexer
   - Secure the Wazuh dashboard with HTTPS
   - Verify Wazuh services are running

4. **Deploy Windows Endpoint**
   - Install Windows 10/11 evaluation VM
   - Install the Wazuh agent
   - Configure Windows Event Log forwarding (Security, System, Application)
   - Verify logs appear in the Wazuh dashboard

5. **Deploy Linux Endpoint**
   - Install Ubuntu Desktop or Server VM
   - Install the Wazuh agent
   - Configure syslog forwarding to Wazuh
   - Verify logs appear in the Wazuh dashboard

6. **Configure Detection Rules**
   - Create a custom rule for failed login attempts (brute force detection)
   - Create a rule for suspicious process execution
   - Create a rule for firewall block events
   - Test rules by simulating attacks in the lab

7. **Build SOC Dashboard**
   - Create a dashboard showing real-time alerts
   - Add widgets for alert counts by severity, source, and rule
   - Build a timeline view of security events
   - Document dashboard navigation and interpretation

8. **Document the Build**
   - Create an architecture diagram
   - Document all configuration steps
   - Write a troubleshooting guide
   - List lessons learned and improvement suggestions

## Deliverables

- Fully functional home SOC lab with SIEM and endpoints
- Architecture diagram showing network topology
- Custom detection rules file
- SOC analyst dashboard configuration
- Build documentation (step-by-step guide)
- Troubleshooting guide
- Screenshots of key configurations and dashboards

## Skills

- Virtualisation (VirtualBox/VMware)
- Linux system administration
- SIEM deployment and configuration (Wazuh)
- Network segmentation and firewall configuration
- Log forwarding and normalisation
- Detection rule creation (Wazuh XML rules)
- SOC dashboard design
- Security architecture documentation
- Attack simulation and testing

## Tools

- VirtualBox or VMware Workstation Player (free)
- Wazuh SIEM (open source)
- Ubuntu Server (free)
- Windows 10/11 Evaluation (free from Microsoft)
- Ubuntu Desktop (free)
- draw.io or Lucidchart for architecture diagrams
- Notepad++ or VS Code for editing configuration files

## Resources

- Wazuh Documentation: https://documentation.wazuh.com/
- Wazuh Installation Guide: https://documentation.wazuh.com/current/installation-guide/index.html
- Windows Evaluation: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise
- VirtualBox: https://www.virtualbox.org/
- VMware Workstation Player: https://www.vmware.com/products/workstation-player.html
- draw.io - Free Diagram Tool: https://app.diagrams.net/
- Wazuh Custom Rules: https://documentation.wazuh.com/current/user-manual/ruleset/custom-rules.html
- MITRE ATT&CK Framework: https://attack.mitre.org/
