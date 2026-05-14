"""
cy_comp/data/annex_a_controls.py
==================================
All 93 ISO/IEC 27001:2022 Annex A controls with:
  - control_id   : canonical reference (e.g. "A.5.1")
  - title        : short control title from the standard
  - theme        : Organisational | People | Physical | Technological
  - section      : sub-grouping within the theme
  - description  : brief statement of what the control requires
  - question_id  : the questionnaire question that assesses this control
                   (None = not directly assessed; requires SoA justification only)

The question_id mapping allows the SoA view to automatically inherit status
from questionnaire responses — if a grouped question covers A.5.20 and the
analyst answered NO, A.5.20 shows as "gap" in the SoA.
"""

ANNEX_A_CONTROLS = [

    # ── Organisational Controls (A.5.1 – A.5.37) ─────────────────────────────

    {"control_id": "A.5.1",  "theme": "Organisational", "section": "Information Security Policies",
     "title": "Policies for information security",
     "description": "Topic-specific IS policies shall be defined, approved, published, communicated and reviewed.",
     "question_id": "iso-org-01"},

    {"control_id": "A.5.2",  "theme": "Organisational", "section": "Information Security Policies",
     "title": "Information security roles and responsibilities",
     "description": "IS roles and responsibilities shall be defined and allocated according to organisational needs.",
     "question_id": "iso-isms-02"},

    {"control_id": "A.5.3",  "theme": "Organisational", "section": "Organisation of IS",
     "title": "Segregation of duties",
     "description": "Conflicting duties and conflicting areas of responsibility shall be segregated.",
     "question_id": "iso-org-02"},

    {"control_id": "A.5.4",  "theme": "Organisational", "section": "Organisation of IS",
     "title": "Management responsibilities",
     "description": "Management shall require all personnel to apply IS per established policies and procedures.",
     "question_id": "iso-org-02"},

    {"control_id": "A.5.5",  "theme": "Organisational", "section": "Organisation of IS",
     "title": "Contact with authorities",
     "description": "Appropriate contacts with relevant authorities shall be established and maintained.",
     "question_id": "iso-org-03"},

    {"control_id": "A.5.6",  "theme": "Organisational", "section": "Organisation of IS",
     "title": "Contact with special interest groups",
     "description": "Appropriate contacts with special interest groups or security forums shall be maintained.",
     "question_id": "iso-org-03"},

    {"control_id": "A.5.7",  "theme": "Organisational", "section": "Threat Intelligence",
     "title": "Threat intelligence",
     "description": "Information relating to IS threats shall be collected, analysed, and applied.",
     "question_id": "iso-org-04"},

    {"control_id": "A.5.8",  "theme": "Organisational", "section": "IS in Project Management",
     "title": "Information security in project management",
     "description": "IS shall be integrated into project management throughout the project lifecycle.",
     "question_id": "iso-org-05"},

    {"control_id": "A.5.9",  "theme": "Organisational", "section": "Asset Management",
     "title": "Inventory of information and other associated assets",
     "description": "An inventory of IS assets and associated assets shall be developed and maintained.",
     "question_id": "iso-org-06"},

    {"control_id": "A.5.10", "theme": "Organisational", "section": "Asset Management",
     "title": "Acceptable use of information and other associated assets",
     "description": "Rules for acceptable use and procedures for handling information and assets shall be identified.",
     "question_id": "iso-org-06"},

    {"control_id": "A.5.11", "theme": "Organisational", "section": "Asset Management",
     "title": "Return of assets",
     "description": "Personnel and other interested parties shall return all assets belonging to the organisation upon change or termination.",
     "question_id": "iso-ppl-04"},

    {"control_id": "A.5.12", "theme": "Organisational", "section": "Asset Management",
     "title": "Classification of information",
     "description": "Information shall be classified according to IS needs based on confidentiality, integrity, availability, and relevant stakeholder requirements.",
     "question_id": "iso-org-06"},

    {"control_id": "A.5.13", "theme": "Organisational", "section": "Asset Management",
     "title": "Labelling of information",
     "description": "An appropriate set of procedures for IS labelling shall be developed and implemented.",
     "question_id": "iso-org-07"},

    {"control_id": "A.5.14", "theme": "Organisational", "section": "Asset Management",
     "title": "Information transfer",
     "description": "IS transfer rules, procedures, or agreements shall be in place for all types of transfer.",
     "question_id": "iso-org-07"},

    {"control_id": "A.5.15", "theme": "Organisational", "section": "Access Control",
     "title": "Access control",
     "description": "Rules to control physical and logical access to information and assets shall be established based on business and IS requirements.",
     "question_id": "iso-org-08"},

    {"control_id": "A.5.16", "theme": "Organisational", "section": "Access Control",
     "title": "Identity management",
     "description": "The full lifecycle of identities shall be managed.",
     "question_id": "iso-org-09"},

    {"control_id": "A.5.17", "theme": "Organisational", "section": "Access Control",
     "title": "Authentication information",
     "description": "Allocation and management of authentication information shall be controlled by a management process.",
     "question_id": "iso-org-09"},

    {"control_id": "A.5.18", "theme": "Organisational", "section": "Access Control",
     "title": "Access rights",
     "description": "Access rights shall be provisioned, reviewed, modified, and removed per the access control policy.",
     "question_id": "iso-org-08"},

    {"control_id": "A.5.19", "theme": "Organisational", "section": "Supplier Relationships",
     "title": "Information security in supplier relationships",
     "description": "Processes and procedures shall be defined to manage IS risks associated with suppliers.",
     "question_id": "iso-org-10"},

    {"control_id": "A.5.20", "theme": "Organisational", "section": "Supplier Relationships",
     "title": "Addressing IS within supplier agreements",
     "description": "Relevant IS requirements shall be established and agreed with each supplier based on risk.",
     "question_id": "iso-org-10"},

    {"control_id": "A.5.21", "theme": "Organisational", "section": "Supplier Relationships",
     "title": "Managing IS in the ICT supply chain",
     "description": "Processes and procedures shall be defined to manage IS risks associated with the ICT supply chain.",
     "question_id": "iso-org-10"},

    {"control_id": "A.5.22", "theme": "Organisational", "section": "Supplier Relationships",
     "title": "Monitoring, review and change management of supplier services",
     "description": "The organisation shall regularly monitor, review, evaluate, and manage changes in supplier IS practices.",
     "question_id": "iso-org-10"},

    {"control_id": "A.5.23", "theme": "Organisational", "section": "Supplier Relationships",
     "title": "Information security for use of cloud services",
     "description": "Processes for acquisition, use, management and exit of cloud services shall address IS requirements.",
     "question_id": "iso-org-10"},

    {"control_id": "A.5.24", "theme": "Organisational", "section": "Incident Management",
     "title": "Information security incident management planning and preparation",
     "description": "The organisation shall plan and prepare for managing IS incidents by defining processes and roles.",
     "question_id": "iso-org-11"},

    {"control_id": "A.5.25", "theme": "Organisational", "section": "Incident Management",
     "title": "Assessment and decision on information security events",
     "description": "IS events shall be assessed and decided whether to classify them as IS incidents.",
     "question_id": "iso-org-11"},

    {"control_id": "A.5.26", "theme": "Organisational", "section": "Incident Management",
     "title": "Response to information security incidents",
     "description": "IS incidents shall be responded to in accordance with the documented procedures.",
     "question_id": "iso-org-11"},

    {"control_id": "A.5.27", "theme": "Organisational", "section": "Incident Management",
     "title": "Learning from information security incidents",
     "description": "Knowledge gained from IS incidents shall be used to strengthen and improve IS controls.",
     "question_id": "iso-org-11"},

    {"control_id": "A.5.28", "theme": "Organisational", "section": "Incident Management",
     "title": "Collection of evidence",
     "description": "Procedures for identification, collection, acquisition, and preservation of evidence shall be defined.",
     "question_id": "iso-org-11"},

    {"control_id": "A.5.29", "theme": "Organisational", "section": "Business Continuity",
     "title": "Information security during disruption",
     "description": "The organisation shall plan how to maintain IS at an appropriate level during disruption.",
     "question_id": "iso-org-12"},

    {"control_id": "A.5.30", "theme": "Organisational", "section": "Business Continuity",
     "title": "ICT readiness for business continuity",
     "description": "ICT readiness shall be planned, implemented, maintained, and tested based on BCP and continuity objectives.",
     "question_id": "iso-org-12"},

    {"control_id": "A.5.31", "theme": "Organisational", "section": "Legal & Compliance",
     "title": "Legal, statutory, regulatory and contractual requirements",
     "description": "Legal, statutory, regulatory and contractual requirements relevant to IS shall be identified and documented.",
     "question_id": "iso-org-13"},

    {"control_id": "A.5.32", "theme": "Organisational", "section": "Legal & Compliance",
     "title": "Intellectual property rights",
     "description": "Procedures shall be implemented to protect intellectual property rights.",
     "question_id": "iso-org-13"},

    {"control_id": "A.5.33", "theme": "Organisational", "section": "Legal & Compliance",
     "title": "Protection of records",
     "description": "Records shall be protected from loss, destruction, falsification, unauthorised access and unauthorised release.",
     "question_id": "iso-org-13"},

    {"control_id": "A.5.34", "theme": "Organisational", "section": "Privacy & Compliance",
     "title": "Privacy and protection of PII",
     "description": "The organisation shall identify and meet privacy and PII protection requirements per applicable legislation.",
     "question_id": "iso-org-14"},

    {"control_id": "A.5.35", "theme": "Organisational", "section": "Privacy & Compliance",
     "title": "Independent review of information security",
     "description": "The organisation's approach to IS shall be reviewed independently at planned intervals.",
     "question_id": "iso-org-14"},

    {"control_id": "A.5.36", "theme": "Organisational", "section": "Privacy & Compliance",
     "title": "Compliance with policies, rules and standards for IS",
     "description": "Compliance with the organisation's IS policy, topic-specific policies, rules and standards shall be regularly reviewed.",
     "question_id": "iso-org-14"},

    {"control_id": "A.5.37", "theme": "Organisational", "section": "IS in Project Management",
     "title": "Documented operating procedures",
     "description": "Operating procedures for IS shall be documented and available to personnel who need them.",
     "question_id": "iso-org-05"},

    # ── People Controls (A.6.1 – A.6.8) ──────────────────────────────────────

    {"control_id": "A.6.1",  "theme": "People", "section": "Pre-Employment",
     "title": "Screening",
     "description": "Background verification checks on all candidates for employment shall be carried out prior to joining.",
     "question_id": "iso-ppl-01"},

    {"control_id": "A.6.2",  "theme": "People", "section": "Pre-Employment",
     "title": "Terms and conditions of employment",
     "description": "Employment contracts shall state IS responsibilities of personnel and the organisation.",
     "question_id": "iso-ppl-02"},

    {"control_id": "A.6.3",  "theme": "People", "section": "Awareness & Training",
     "title": "Information security awareness, education and training",
     "description": "All personnel shall receive appropriate IS awareness and training relevant to their role.",
     "question_id": "iso-ppl-03"},

    {"control_id": "A.6.4",  "theme": "People", "section": "Disciplinary Process",
     "title": "Disciplinary process",
     "description": "A disciplinary process shall be formalised and communicated to take actions against those who have committed an IS policy violation.",
     "question_id": "iso-ppl-04"},

    {"control_id": "A.6.5",  "theme": "People", "section": "Termination & Change",
     "title": "Responsibilities after termination or change of employment",
     "description": "IS responsibilities and duties that remain valid after termination shall be defined, enforced, and communicated.",
     "question_id": "iso-ppl-04"},

    {"control_id": "A.6.6",  "theme": "People", "section": "Termination & Change",
     "title": "Confidentiality or non-disclosure agreements",
     "description": "NDAs reflecting the organisation's needs for protecting IS shall be identified, documented, and reviewed.",
     "question_id": "iso-ppl-04"},

    {"control_id": "A.6.7",  "theme": "People", "section": "Remote Working",
     "title": "Remote working",
     "description": "Security measures shall be implemented when personnel are working remotely.",
     "question_id": "iso-ppl-05"},

    {"control_id": "A.6.8",  "theme": "People", "section": "IS Event Reporting",
     "title": "Information security event reporting",
     "description": "Mechanisms shall exist for personnel to report observed or suspected IS events through appropriate channels.",
     "question_id": "iso-ppl-05"},

    # ── Physical Controls (A.7.1 – A.7.14) ───────────────────────────────────

    {"control_id": "A.7.1",  "theme": "Physical", "section": "Physical Security Perimeter",
     "title": "Physical security perimeters",
     "description": "Security perimeters shall be defined and used to protect areas containing information and assets.",
     "question_id": "iso-phy-01"},

    {"control_id": "A.7.2",  "theme": "Physical", "section": "Physical Security Perimeter",
     "title": "Physical entry",
     "description": "Secure areas shall be protected by appropriate entry controls to ensure only authorised personnel are allowed access.",
     "question_id": "iso-phy-01"},

    {"control_id": "A.7.3",  "theme": "Physical", "section": "Physical Security Perimeter",
     "title": "Securing offices, rooms and facilities",
     "description": "Physical security for offices, rooms, and facilities shall be designed and implemented.",
     "question_id": "iso-phy-02"},

    {"control_id": "A.7.4",  "theme": "Physical", "section": "Physical Security Perimeter",
     "title": "Physical security monitoring",
     "description": "Premises shall be continuously monitored for unauthorised physical access.",
     "question_id": "iso-phy-01"},

    {"control_id": "A.7.5",  "theme": "Physical", "section": "Physical Security Perimeter",
     "title": "Protecting against physical and environmental threats",
     "description": "Protection against natural disasters, deliberate attack, or accidents shall be designed and implemented.",
     "question_id": "iso-phy-02"},

    {"control_id": "A.7.6",  "theme": "Physical", "section": "Working in Secure Areas",
     "title": "Working in secure areas",
     "description": "Security measures for working in secure areas shall be designed and implemented.",
     "question_id": "iso-phy-03"},

    {"control_id": "A.7.7",  "theme": "Physical", "section": "Working in Secure Areas",
     "title": "Clear desk and clear screen",
     "description": "Clear desk rules for papers and removable storage media and clear screen rules shall be defined and enforced.",
     "question_id": "iso-phy-03"},

    {"control_id": "A.7.8",  "theme": "Physical", "section": "Equipment Security",
     "title": "Equipment siting and protection",
     "description": "Equipment shall be sited securely and protected to reduce risks from environmental threats and unauthorised access.",
     "question_id": "iso-phy-04"},

    {"control_id": "A.7.9",  "theme": "Physical", "section": "Equipment Security",
     "title": "Security of assets off-premises",
     "description": "Off-site assets shall be protected by considering the different risks from working outside the organisation's premises.",
     "question_id": "iso-phy-05"},

    {"control_id": "A.7.10", "theme": "Physical", "section": "Equipment Security",
     "title": "Storage media",
     "description": "Storage media shall be managed through their lifecycle of acquisition, use, transportation and disposal.",
     "question_id": "iso-phy-05"},

    {"control_id": "A.7.11", "theme": "Physical", "section": "Equipment Security",
     "title": "Supporting utilities",
     "description": "Information processing facilities shall be protected from power failures and disruptions caused by supporting utilities.",
     "question_id": "iso-phy-04"},

    {"control_id": "A.7.12", "theme": "Physical", "section": "Equipment Security",
     "title": "Cabling security",
     "description": "Cables carrying power, data, or supporting IS shall be protected from interception, interference or damage.",
     "question_id": "iso-phy-04"},

    {"control_id": "A.7.13", "theme": "Physical", "section": "Equipment Security",
     "title": "Equipment maintenance",
     "description": "Equipment shall be maintained correctly to ensure availability, integrity, and confidentiality of information.",
     "question_id": "iso-phy-04"},

    {"control_id": "A.7.14", "theme": "Physical", "section": "Equipment Security",
     "title": "Secure disposal or re-use of equipment",
     "description": "Items of equipment containing storage media shall be verified that sensitive data has been removed prior to disposal.",
     "question_id": "iso-phy-05"},

    # ── Technological Controls (A.8.1 – A.8.34) ──────────────────────────────

    {"control_id": "A.8.1",  "theme": "Technological", "section": "Endpoint Security",
     "title": "User endpoint devices",
     "description": "Information stored on, processed by, or accessible via user endpoint devices shall be protected.",
     "question_id": "iso-tech-01"},

    {"control_id": "A.8.2",  "theme": "Technological", "section": "Privileged Access",
     "title": "Privileged access rights",
     "description": "Allocation and use of privileged access rights shall be restricted and managed.",
     "question_id": "iso-tech-02"},

    {"control_id": "A.8.3",  "theme": "Technological", "section": "Access Control",
     "title": "Information access restriction",
     "description": "Access to information and application system functions shall be restricted in accordance with the access control policy.",
     "question_id": "iso-tech-03"},

    {"control_id": "A.8.4",  "theme": "Technological", "section": "Access Control",
     "title": "Access to source code",
     "description": "Read and write access to source code, development tools, and software libraries shall be appropriately managed.",
     "question_id": "iso-tech-03"},

    {"control_id": "A.8.5",  "theme": "Technological", "section": "Access Control",
     "title": "Secure authentication",
     "description": "Secure authentication technologies and procedures shall be implemented based on information access restrictions.",
     "question_id": "iso-tech-03"},

    {"control_id": "A.8.6",  "theme": "Technological", "section": "Capacity Management",
     "title": "Capacity management",
     "description": "The use of resources shall be monitored and adjusted in line with current and expected capacity requirements.",
     "question_id": "iso-tech-04"},

    {"control_id": "A.8.7",  "theme": "Technological", "section": "Malware Protection",
     "title": "Protection against malware",
     "description": "Protection against malware shall be implemented and supported by appropriate user awareness.",
     "question_id": "iso-tech-04"},

    {"control_id": "A.8.8",  "theme": "Technological", "section": "Vulnerability Management",
     "title": "Management of technical vulnerabilities",
     "description": "Information about technical vulnerabilities of systems shall be obtained, the organisation's exposure evaluated, and appropriate measures taken.",
     "question_id": "iso-tech-04"},

    {"control_id": "A.8.9",  "theme": "Technological", "section": "Configuration Management",
     "title": "Configuration management",
     "description": "Configurations, including security configurations, of hardware, software, services, and networks shall be established, documented, implemented, monitored, and reviewed.",
     "question_id": "iso-tech-05"},

    {"control_id": "A.8.10", "theme": "Technological", "section": "Data Protection",
     "title": "Information deletion",
     "description": "Information stored in IS and devices shall be deleted when no longer required.",
     "question_id": "iso-tech-06"},

    {"control_id": "A.8.11", "theme": "Technological", "section": "Data Protection",
     "title": "Data masking",
     "description": "Data masking shall be used in accordance with the organisation's topic-specific policy on access control.",
     "question_id": "iso-tech-06"},

    {"control_id": "A.8.12", "theme": "Technological", "section": "Data Protection",
     "title": "Data leakage prevention",
     "description": "Data leakage prevention measures shall be applied to systems, networks and other devices that process, store or transmit sensitive information.",
     "question_id": "iso-tech-06"},

    {"control_id": "A.8.13", "theme": "Technological", "section": "Backup & Recovery",
     "title": "Information backup",
     "description": "Backup copies of information, software, and systems shall be maintained and tested in accordance with the agreed backup policy.",
     "question_id": "iso-tech-07"},

    {"control_id": "A.8.14", "theme": "Technological", "section": "Backup & Recovery",
     "title": "Redundancy of information processing facilities",
     "description": "Facilities shall be implemented with sufficient redundancy to meet availability requirements.",
     "question_id": "iso-tech-07"},

    {"control_id": "A.8.15", "theme": "Technological", "section": "Logging & Monitoring",
     "title": "Logging",
     "description": "Logs that record activities, exceptions, faults, and other relevant events shall be produced, stored, protected, and analysed.",
     "question_id": "iso-tech-08"},

    {"control_id": "A.8.16", "theme": "Technological", "section": "Logging & Monitoring",
     "title": "Monitoring activities",
     "description": "Networks, systems, and applications shall be monitored for anomalous behaviour and to evaluate potential security incidents.",
     "question_id": "iso-tech-08"},

    {"control_id": "A.8.17", "theme": "Technological", "section": "Logging & Monitoring",
     "title": "Clock synchronisation",
     "description": "Clocks of information processing systems shall be synchronised to approved time sources.",
     "question_id": "iso-tech-08"},

    {"control_id": "A.8.18", "theme": "Technological", "section": "System Controls",
     "title": "Use of privileged utility programs",
     "description": "The use of utility programs that can override system and application controls shall be restricted and tightly controlled.",
     "question_id": "iso-tech-09"},

    {"control_id": "A.8.19", "theme": "Technological", "section": "System Controls",
     "title": "Installation of software on operational systems",
     "description": "Procedures and measures shall be implemented to securely manage software installation on operational systems.",
     "question_id": "iso-tech-09"},

    {"control_id": "A.8.20", "theme": "Technological", "section": "Network Security",
     "title": "Networks security",
     "description": "Networks and network devices shall be secured, managed, and controlled to protect information in systems and applications.",
     "question_id": "iso-tech-10"},

    {"control_id": "A.8.21", "theme": "Technological", "section": "Network Security",
     "title": "Security of network services",
     "description": "Security mechanisms, service levels, and service requirements of network services shall be identified, implemented, and monitored.",
     "question_id": "iso-tech-10"},

    {"control_id": "A.8.22", "theme": "Technological", "section": "Network Security",
     "title": "Segregation of networks",
     "description": "Groups of information services, users, and systems shall be segregated in the organisation's networks.",
     "question_id": "iso-tech-10"},

    {"control_id": "A.8.23", "theme": "Technological", "section": "Network Security",
     "title": "Web filtering",
     "description": "Access to external websites shall be managed to reduce exposure to malicious content.",
     "question_id": "iso-tech-10"},

    {"control_id": "A.8.24", "theme": "Technological", "section": "Cryptography",
     "title": "Use of cryptography",
     "description": "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
     "question_id": "iso-tech-11"},

    {"control_id": "A.8.25", "theme": "Technological", "section": "Secure Development",
     "title": "Secure development life cycle",
     "description": "Rules for the secure development of software and systems shall be established and applied.",
     "question_id": "iso-tech-12"},

    {"control_id": "A.8.26", "theme": "Technological", "section": "Secure Development",
     "title": "Application security requirements",
     "description": "IS requirements shall be identified, specified and approved when developing or acquiring applications.",
     "question_id": "iso-tech-12"},

    {"control_id": "A.8.27", "theme": "Technological", "section": "Secure Development",
     "title": "Secure system architecture and engineering principles",
     "description": "Principles for engineering secure systems shall be established, documented, maintained and applied.",
     "question_id": "iso-tech-12"},

    {"control_id": "A.8.28", "theme": "Technological", "section": "Secure Development",
     "title": "Secure coding",
     "description": "Secure coding principles shall be applied to software development.",
     "question_id": "iso-tech-12"},

    {"control_id": "A.8.29", "theme": "Technological", "section": "Secure Development",
     "title": "Security testing in development and acceptance",
     "description": "Security testing processes shall be defined and implemented in the development lifecycle.",
     "question_id": "iso-tech-12"},

    {"control_id": "A.8.30", "theme": "Technological", "section": "Secure Development",
     "title": "Outsourced development",
     "description": "The organisation shall supervise and monitor outsourced system development activities.",
     "question_id": "iso-tech-13"},

    {"control_id": "A.8.31", "theme": "Technological", "section": "Secure Development",
     "title": "Separation of development, test and production environments",
     "description": "Development, testing, and production environments shall be separated and secured.",
     "question_id": "iso-tech-13"},

    {"control_id": "A.8.32", "theme": "Technological", "section": "Change Management",
     "title": "Change management",
     "description": "Changes to IS, information processing facilities, and IS shall be subject to change management procedures.",
     "question_id": "iso-tech-12"},

    {"control_id": "A.8.33", "theme": "Technological", "section": "Secure Development",
     "title": "Test information",
     "description": "Test information shall be appropriately selected, protected, and managed.",
     "question_id": "iso-tech-13"},

    {"control_id": "A.8.34", "theme": "Technological", "section": "Audit Protection",
     "title": "Protection of information systems during audit testing",
     "description": "Audit tests and other assurance activities involving assessment of operational systems shall be planned and agreed.",
     "question_id": "iso-tech-13"},
]

# Quick lookup: control_id → entry
ANNEX_A_BY_ID = {c["control_id"]: c for c in ANNEX_A_CONTROLS}

# Theme grouping for UI rendering
THEME_ORDER = ["Organisational", "People", "Physical", "Technological"]
THEME_COUNTS = {
    "Organisational": 37,
    "People": 8,
    "Physical": 14,
    "Technological": 34,
}
