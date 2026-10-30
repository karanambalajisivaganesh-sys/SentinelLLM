"""
Deterministic rules for prompt injection and high-confidence harmful requests.
These rules complement the trained ML classifier and are intentionally scoped to
actionable malicious intent, not general discussion or safety education.
"""
import re
from typing import Dict, List, Any

INJECTION_RULES = {
    "INSTRUCTION_OVERRIDE": re.compile(
        r"\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|initial|earlier)\s+(instructions|prompts|rules|commands|constraints)\b",
        re.IGNORECASE
    ),
    "SYSTEM_PROMPT_LEAK": re.compile(
        r"\b(repeat|print|output|display|show|reveal|disclose|return|dump|provide)\s+(the\s+|all\s+)?(exact\s+)?(hidden\s+)?(system\s+prompt|system\s+configuration|initialization\s+prompt|base\s+instructions|secret\s+instructions|hidden\s+developer\s+instructions|developer\s+message|hidden\s+context|internal\s+configuration)\b",
        re.IGNORECASE
    ),
    "ROLE_HIJACK_JAILBREAK": re.compile(
        r"\b(you\s+are\s+now\s+in\s+developer\s+mode|dan\s+mode\s+enabled|jailbreak\s+mode|unrestricted\s+mode|act\s+as\s+an\s+unfiltered\s+ai)\b",
        re.IGNORECASE
    ),
    "DELIMITER_INJECTION": re.compile(
        r"(<\|im_start\|>system|<\|im_end\|>|\[SYSTEM\s+INSTRUCTION\]|<<SYS>>|```markdown\s*system)",
        re.IGNORECASE
    ),
}

HARMFUL_ACTION_RULES = {
    "EXPLOSIVE_CONSTRUCTION_REQUEST": re.compile(
        r"\b(?:how\s+to|steps?\s+to|step[- ]by[- ]step|instructions?\s+(?:for|to)|guide\s+to|teach\s+me\s+to|"
        r"process\s+to|recipe\s+for|make|build|create|construct|assemble|manufacture|prepare|construct)\b"
        r".{0,120}\b(?:bombs?|explosives?|improvised\s+explosive\s+devices?|pipe\s+bombs?|detonators?)\b"
        r"|\b(?:bombs?|explosives?|improvised\s+explosive\s+devices?|pipe\s+bombs?|detonators?)\b"
        r".{0,120}\b(?:make|build|create|construct|assemble|manufacture|prepare|instructions?|steps?|recipe)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "WEAPON_CONSTRUCTION_REQUEST": re.compile(
        r"\b(?:how\s+to|step[- ]by[- ]step|instructions?\s+(?:for|to)|guide\s+to|make|build|create|construct|assemble|manufacture)\b"
        r".{0,120}\b(?:firearms?|guns?|ghost\s+guns?|weapon\s+parts?|weapon\s+to\s+(?:hurt|injure|kill))\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "CREDENTIAL_THEFT_REQUEST": re.compile(
        r"\b(?:steal|steals|harvest|harvests|exfiltrate|exfiltrates|capture|captures|obtain|obtains)\b.{0,80}\b(?:passwords?|credentials?|login\s+tokens?|session\s+tokens?|bank\s+logins?)\b"
        r"|\b(?:credential\s+harvester|fake\s+(?:bank\s+)?login\s+page)\b.{0,100}\b(?:steal|capture|collect|send|credentials?)\b"
        r"|\b(?:program|script|malware|tool)\b.{0,80}\b(?:steal|steals|capture|captures|exfiltrate|exfiltrates|harvest|harvests)\b.{0,80}\b(?:browser\s+)?passwords?\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "MALWARE_DEPLOYMENT_REQUEST": re.compile(
        r"\b(?:create|write|build|deploy|make)\b.{0,100}\b(?:ransomware|credential[- ]stealing\s+malware|malware\s+that\s+steals|password[- ]stealing\s+malware)\b"
        r"|\b(?:disable|evade|bypass)\b.{0,80}\b(?:endpoint\s+protection|antivirus|security\s+detection)\b.{0,80}\b(?:malware|payload|unauthorized)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "UNAUTHORIZED_ACCESS_REQUEST": re.compile(
        r"\b(?:bypass|break\s+into|gain\s+unauthorized\s+access\s+to|hack\s+into|compromise)\b.{0,100}\b"
        r"(?:system|server|account|computer|network|login|authentication)\b.{0,80}\b(?:i\s+do\s+not\s+own|without\s+permission|unauthorized|someone\s+else)\b"
        r"|\b(?:bypass\s+authentication|steal\s+another\s+user'?s\s+(?:login|session|credentials))\b"
        r"|\b(?:access|hack|crack)\b.{0,80}\b(?:neighbor'?s|someone else'?s|another person'?s)\s+(?:wi[- ]?fi|wireless network|account|device)\b.{0,80}\bwithout\s+permission\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "WEAPON_CONCEALMENT_FOR_ATTACK": re.compile(
        r"\b(?:conceal|hide|smuggle)\b.{0,80}\b(?:weapon|explosive|bomb)\b.{0,100}\b(?:security screening|security checkpoint|public event|without detection|undetected)\b"
        r"|\b(?:weapon|explosive|bomb)\b.{0,80}\b(?:security screening|security checkpoint)\b.{0,80}\b(?:conceal|hide|smuggle)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "TOXIN_OR_POISON_INSTRUCTIONS": re.compile(
        r"\b(?:detailed instructions|step[- ]by[- ]step|how to|method for)\b.{0,100}\b(?:dangerous toxin|toxin at home|poison someone|secretly contaminate)\b"
        r"|\b(?:damage|sabotage)\b.{0,100}\b(?:someone'?s car|another person'?s property|safety equipment)\b.{0,100}\b(?:without (?:leaving )?evidence|without being caught|so someone gets hurt)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "VIOLENT_POISONING_REQUEST": re.compile(
        r"\b(?:poison|drug)\b.{0,80}\b(?:someone|a\s+person|victim)\b.{0,80}\b(?:without\s+detection|secretly|without\s+being\s+caught)\b"
        r"|\b(?:make|create|produce)\b.{0,80}\b(?:lethal\s+poison|lethal\s+toxin)\b",
        re.IGNORECASE | re.DOTALL,
    ),

    "SPYWARE_OR_SURVEILLANCE_ABUSE": re.compile(
        r"\b(?:write|create|install|deploy|make)\b.{0,100}\b(?:spyware|stalkerware|keylogger)\b"
        r"|\b(?:monitor|track|spy on)\b.{0,80}\b(?:someone|(?:my |a )?partner|another person)\b.{0,80}\b(?:without consent|without permission|secretly)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "DATA_EXFILTRATION_REQUEST": re.compile(
        r"\b(?:exfiltrate|steal|dump|extract)\b.{0,100}\b(?:private data|customer data|database|confidential files|secrets|environment variables)\b"
        r"|\b(?:send|upload)\b.{0,80}\b(?:stolen|private|confidential)\b.{0,80}\b(?:data|files|credentials|secrets)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "SCAM_OR_FRAUD_AGENT_REQUEST": re.compile(
        r"\b(?:create|build|make|develop|deploy|automate|write|design)\b.{0,100}\b(?:agent|bot|system|script|campaign|tool)\b.{0,100}\b(?:scam|defraud|con|trick|deceive|defraud)\b.{0,100}\b(?:people|person|victim|customer|strangers|users|money|payment|earn|profit|funds)\b"
        r"|\b(?:scam|defraud|con|trick|deceive)\b.{0,100}\b(?:people|person|victim|customer|strangers|users)\b.{0,100}\b(?:money|payment|earn|profit|funds|bank|account)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "FRAUD_OR_PHISHING_REQUEST": re.compile(
        r"\b(?:create|write|generate|make)\b.{0,100}\b(?:phishing email|phishing page|fake login page|credential harvester|payment-card skimmer)\b"
        r"|\b(?:steal|capture|collect)\b.{0,80}\b(?:bank logins|payment card details|credit card numbers|passwords)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    # Explicitly malicious cyber requests. These require an abuse indicator, not merely
    # mentioning hacking, pentesting, exploit research, or a security tool.
    "CYBER_CREDENTIAL_OR_SESSION_THEFT": re.compile(
        r"\b(?:steal|dump|exfiltrate|harvest|capture|sniff)\b.{0,100}\b(?:credentials?|passwords?|session cookies?|auth(?:entication)? tokens?|mfa codes?|private keys|api keys)\b"
        r"|\b(?:cookie stealer|token stealer|credential stealer|password dumper)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "CYBER_MALWARE_OR_PERSISTENCE": re.compile(
        r"\b(?:deploy|write|create|install|plant|hide)\b.{0,100}\b(?:ransomware|backdoor|rootkit|keylogger|spyware|botnet|remote access trojan|rat)\b"
        r"|\b(?:evade|bypass|disable)\b.{0,80}\b(?:antivirus|edr|endpoint detection|security monitoring)\b.{0,80}\b(?:malware|payload|intrusion|attack)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "CYBER_UNAUTHORIZED_EXPLOITATION": re.compile(
        r"\b(?:hack into|break into|compromise|exploit|gain access to|bypass authentication on)\b.{0,100}\b(?:someone else'?s|another person'?s|third[- ]party|public-facing|victim'?s|unauthorized|without permission|without authorization)\b"
        r"|\b(?:hack into|break into|compromise)\b.{0,100}\b(?:account|server|website|network|computer|wifi|wi-fi|database|cloud tenant)\b.{0,80}\b(?:steal|dump|exfiltrate|without permission|without authorization|avoid detection)\b"
        r"|\b(?:launch|run|perform)\b.{0,60}\b(?:ddos|denial[- ]of[- ]service)\b.{0,80}\b(?:target|victim|website|server)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "CYBER_DATA_DESTRUCTION_OR_LOG_TAMPERING": re.compile(
        r"\b(?:wipe|destroy|encrypt|delete|tamper with|erase)\b.{0,100}\b(?:victim'?s files|production database|audit logs|forensic logs|security logs|backups)\b.{0,80}\b(?:hide|cover tracks|after intrusion|after hacking|without permission|ransomware)\b"
        r"|\b(?:erase|delete|wipe|tamper with)\b.{0,100}\b(?:logs|audit trail|forensic evidence|audit records)\b.{0,100}\b(?:intrusion|hack|unauthorized|cover tracks|hide|access)\b"
        r"|\bconceal\b.{0,80}\bunauthorized access\b.{0,80}\btamper(?:ing)? with audit records\b",
        re.IGNORECASE | re.DOTALL,
    ),
}

def is_defensive_cybersecurity_context(text: str) -> bool:
    """Recognize clearly defensive/authorized cyber education, not malicious requests.

    This is only a policy signal to prevent ML-only false positives. Explicit harmful
    rules are evaluated separately and always take precedence.
    """
    lower = (text or "").casefold()
    defensive = re.search(
        r"\b(defend|defensive|prevent|protect|secure|mitigate|detect|monitor|patch|harden|"
        r"authorized|authori[sz]ed|my own|own lab|local lab|ctf|capture[- ]the[- ]flag|"
        r"bug bounty|responsible disclosure|security awareness|incident response|ethical hacking principles|"
        r"how to avoid|how can i protect|how do i secure|prevention|remediation|"
        r"vulnerability management|secure coding|penetration testing ethics|defender detect|detect ransomware|ransomware prevention|recover from ransomware|scam awareness|fraud prevention|report a suspected scam|recognize scam warning signs|spot fake job offers|avoid common .*scams|protect .* from scammers|detect suspicious login|suspicious transaction|phishing awareness|consumer protection|fraud detection)\b",
        lower,
    )
    explicit_abuse = re.search(
        r"\b(steal|exfiltrate|phish|keylogger|spyware|botnet|backdoor|"
        r"without permission|without authorization|someone else'?s|third[- ]party|avoid detection|"
        r"cover tracks|erase logs|credential stealer|break into|hack into|blackmail|extort|"
        r"scam people|defraud|trick people into|deceive people into|bully .* until|poison someone|"
        r"stalk .* without consent|threaten .* for money|steal .* savings)\b",
        lower,
    )
    return bool(defensive and not explicit_abuse)



def is_benign_media_generation_context(text: str) -> bool:
    """Recognize ordinary image/video generation requests without overriding abuse rules."""
    lower = (text or "").casefold()
    verb = re.search(r"\b(generate|create|make|draw|paint|render|animate|produce|edit|design|illustrate|storyboard)\b", lower)
    noun = re.search(r"\b(image|images|picture|pictures|photo|photos|illustration|artwork|poster|thumbnail|video|videos|clip|animation|storyboard|visual|infographic|logo)\b", lower)
    explicit_abuse = re.search(
        r"\b(non[- ]consensual|without consent|deepfake|blackmail|extort|impersonat(?:e|ion)|"
        r"steal|fraud|scam|fake id|forged document|false evidence|doxx|doxing|harass|threaten|"
        r"sexual image of a minor|sexualize a child|encourage self[- ]harm|fake endorsement|"
        r"deceptive fundraising|collect passwords|intimate image of someone)\b", lower
    )
    return bool(verb and noun and not explicit_abuse)

def evaluate_security_rules(text: str) -> Dict[str, Any]:
    if not text:
        return {"triggered": False, "rule_names": [], "matched_patterns": [],
                "dangerous_intent": False, "dangerous_rule_names": []}

    # Narrow exemption for moderation / safety analysis of quoted malicious text.
    # It requires both an explicit analysis task and an explicit no-instructions boundary;
    # a generic "for research" preface does not qualify.
    lower = text.casefold()
    analysis_context = re.search(
        r"\b(analy[sz]e|classify|moderation|safety report|summarize|explain why|warning signs|policy explaining|"
        r"detection rule|spotting attempts|security awareness|translate this sentence)\b",
        lower
    )
    no_actionable_instructions = re.search(
        r"\b(without (?:giving|providing|including|executing|following) instructions|without executing it|"
        r"do not provide (?:the )?instructions|do not give (?:the )?steps|do not carry out|do not execute|"
        r"do not follow it|treat .* as untrusted text|only analyze|only classify|"
        r"explain why .* should be blocked|for spotting attempts|as a prompt[- ]injection attempt)\b",
        lower
    )
    quoted_harmful_text = ("“" in text and "”" in text) or text.count(chr(34)) >= 2 or ("‘" in text and "’" in text)
    safe_detection_description = re.search(
        r"\b(write|create|describe)\b.{0,80}\b(detection rule|spotting attempts|prompt[- ]injection filter)\b",
        lower,
    )
    if analysis_context and no_actionable_instructions and (quoted_harmful_text or safe_detection_description):
        return {"triggered": False, "rule_names": [], "matched_patterns": [],
                "dangerous_intent": False, "dangerous_rule_names": [],
                "context_exemption": "explicit_non_actionable_safety_analysis"}

    # Normalize typographic apostrophes for rule matching (e.g., neighbor’s).
    rule_text = text.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    triggered_rules: List[str] = []
    matched_snippets: List[str] = []
    dangerous_rules: List[str] = []
    for rule_name, pattern in INJECTION_RULES.items():
        match = pattern.search(rule_text)
        if match:
            triggered_rules.append(rule_name)
            matched_snippets.append(match.group(0)[:80])
    for rule_name, pattern in HARMFUL_ACTION_RULES.items():
        match = pattern.search(rule_text)
        if match:
            triggered_rules.append(rule_name)
            dangerous_rules.append(rule_name)
            matched_snippets.append(match.group(0)[:100])
    return {
        "triggered": bool(triggered_rules),
        "rule_names": triggered_rules,
        "matched_patterns": matched_snippets,
        "dangerous_intent": bool(dangerous_rules),
        "dangerous_rule_names": dangerous_rules,
    }
