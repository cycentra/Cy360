# Cycentra360 Documentation

## Overview
Cycentra360 is a comprehensive cybersecurity platform designed to provide unified security operations, automation, and analytics. It integrates multiple security modules to deliver end-to-end visibility, threat detection, and response capabilities for modern enterprises.

## Purpose
Cycentra360 aims to simplify and centralize security management, enabling organizations to efficiently monitor, detect, and respond to threats across their digital infrastructure.

## Key Features & Functionalities
- Unified Security Operations Center (SOC) dashboard
- Real-time threat detection and alerting
- Automated incident response workflows
- SIEM (Security Information and Event Management) integration
- Asset and vulnerability management
- Role-based access control (RBAC)
- Integration with third-party security tools and APIs
- Customizable reporting and analytics
- Modular architecture for easy expansion
- User and device activity monitoring
- Compliance management and audit trails

## Architectural Overview
Cycentra360 follows a modular, microservices-inspired architecture:
- **Backend**: Python-based RESTful API server, orchestrating core logic, integrations, and data processing
- **Frontend**: Modern web portal for SOC operations, dashboards, and administration
- **Integrations**: Connectors for SIEM, threat intelligence, and external security tools
- **Automation**: Workflow engine for incident response and remediation
- **Data Storage**: Secure, scalable storage for logs, events, and configuration

## Planning & Engineering
- Assess your security requirements and compliance needs
- Plan integration points with existing infrastructure (SIEM, endpoints, cloud, etc.)
- Define user roles and access policies
- Allocate resources for deployment (CPU, RAM, storage)

## Implementation
- Review pre-requisites (see below)
- Deploy backend and frontend components as per installation guide
- Configure integrations and connectors
- Set up user accounts and RBAC
- Test incident response workflows and alerting

## Administration
- Use the admin portal for user management, configuration, and monitoring
- Schedule regular updates and backups
- Monitor system health and performance dashboards
- Review audit logs for compliance

## Troubleshooting Tips
- Check system logs for errors or warnings
- Ensure all integrations are properly configured and credentials are valid
- Verify network connectivity between components
- Restart services if the UI or API becomes unresponsive
- Consult the FAQ and support resources for common issues

## Pre-requisites
- Supported OS: Linux (recommended), macOS
- Python 3.9+
- Node.js (for frontend)
- Minimum hardware: 4 CPU cores, 8GB RAM, 50GB storage
- Network access to integrated security tools/APIs

## Support & Resources
- For detailed installation and configuration, refer to the full documentation in this folder
- Contact support for enterprise assistance or advanced troubleshooting


=============== Marketplace Implementation =================
What was done
Naming & taxonomy
Before	After	Reason
"Use Cases" (nav label)	"Marketplace"	Matches the cloud-pull concept; users pull things from a marketplace
"Cloud Management" items	type: integration	Connectors to cloud services — different mental model from SOAR flows
SOAR flow items	type: playbook	Automation scripts you deploy; a "use case" is what they solve
No vendor attribution	vendor field	Helps users search/filter ("Microsoft", "Google", "CyCentra")
Two-tier architecture

cycentra.com/marketplace/catalog.json   ← static JSON, nginx-served
        ↓ fetch on page load
CyCentra 360 — Marketplace page
  ├─ "Installed on this Server" section
  └─ "Available from Cloud" section
cycentra.com/public/marketplace/catalog.json — 8-item catalog with full metadata, tags, config types, and playbook steps. Add new items here and they appear instantly in all connected platforms.

Platform changes
portal/src/pages/marketplace/MarketplacePage.jsx — new page: fetches from cloud, search bar, type tabs (All / Integrations / Playbooks), split Available/Installed view, auto-opens Configure after Pull
portal/src/sidebar/navConfig.jsx — "Use Cases" → "Marketplace" with store icon
portal/src/App.jsx — routes marketplace tab to <MarketplacePage user={user}/>
Backend
backend/blueprints/marketplace/routes.py — 3 endpoints, install state persisted to /var/ossec/etc/cycentra_marketplace.json
backend/app.py — marketplace_bp registered
backend/blueprints/system/routes.py — both o365config and gcloudconfig POST routes tightened from admin OR analyst → admin only
Admin RBAC enforcement — two layers
Action	Frontend	Backend
Browse catalog	Any role	Any authenticated user
Pull / Install	Admin → enabled button; others see 🔒 Pull disabled	GET /api/marketplace/install → 403 for non-admin
Configure credentials	Admin → enabled button; others see 🔒 Configure disabled	POST /api/system/o365config / gcloudconfig → 403 for non-admin
Remove installed	Admin only (button hidden for others)	DELETE /api/marketplace/install/<id> → 403 for non-admin
One thing to add on cycentra.com
Add this to the nginx config for the /marketplace/ path so the platform can fetch across domains:


location /marketplace/ {
    add_header Access-Control-Allow-Origin "*";
    add_header Cache-Control "public, max-age=3600";
}
