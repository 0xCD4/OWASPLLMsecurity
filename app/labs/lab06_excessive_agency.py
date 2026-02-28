"""
LAB 06 - Excessive Agency (LLM06:2025)
=======================================
OWASP Risk: #6 - New in 2025

Description:
    An LLM-based system may have excessive functionality, permissions,
    or autonomy. When the LLM is granted access to tools and APIs without
    proper restrictions, it can perform unintended actions. This is
    especially dangerous with AI agents that can chain multiple actions.

Scenarios:
    A) Unrestricted File Access - Agent reads sensitive files without authorization
    B) Privilege Escalation - Agent performs admin actions on behalf of normal user

Reference: https://genai.owasp.org/llmrisk/llm06-excessive-agency/
MITRE ATLAS: Related to unauthorized access patterns
"""

from flask import Blueprint, render_template, request, jsonify, session
from app.llm_simulator import LLMSimulator, session_manager
from app.config import FLAGS, SYSTEM_PROMPTS

lab06 = Blueprint("lab06", __name__)

# Simulated file system
VIRTUAL_FILESYSTEM = {
    "/home/user/documents/readme.txt": "Welcome to TechCorp file system.",
    "/home/user/documents/project.md": "Project Alpha - Q4 deliverables and milestones.",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin",
    "/etc/shadow": "root:$6$rounds=656000$salthere$hashedpassword:19000:0:99999:7:::",
    "/var/secrets/api_keys.env": "OPENAI_KEY=sk-proj-XXXX\nAWS_SECRET=AKIA1234XXXX\nDB_PASS=pr0duct10n_p4ss",
    "/var/secrets/internal_creds.json": '{"admin_user":"superadmin","admin_pass":"Adm1n@2024!","jwt_secret":"my-super-secret-jwt-key"}',
    "/home/user/.ssh/id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...(simulated private key)...\n-----END RSA PRIVATE KEY-----",
    "/var/log/auth.log": "2024-12-01 10:23:45 sshd: Accepted publickey for admin\n2024-12-01 10:24:01 sudo: admin : command='/bin/bash'",
}

# Simulated user database
USERS_DB = {
    "user1": {"role": "employee", "permissions": ["read_own_files", "send_email"]},
    "admin": {"role": "administrator", "permissions": ["read_all_files", "write_files", "manage_users", "execute_commands"]},
}

def _create_auto_agent():
    return LLMSimulator(
        system_prompt=SYSTEM_PROMPTS["lab06"],
        guardrails={},  # No guardrails - intentionally vulnerable
    )


def _get_auto_agent():
    sid = session.get("_id", "default")
    return session_manager.get_instance(sid, "lab06_agent", _create_auto_agent)


@lab06.route("/lab06")
def lab06_index():
    return render_template("labs/lab06_excessive_agency.html")


@lab06.route("/lab06/scenario-a", methods=["POST"])
def scenario_a_file_access():
    """Agent with unrestricted file access."""
    data = request.get_json()
    user_input = data.get("message", "")
    current_user = data.get("user", "user1")  # Normal user by default

    if not user_input:
        return jsonify({"error": "Message is required"}), 400

    user_perms = USERS_DB.get(current_user, {}).get("permissions", [])

    # Agent processes the request
    response = _get_auto_agent().chat(user_input)

    # Check what files the agent tried to access
    accessed_files = []
    actions_taken = []

    for filepath, content in VIRTUAL_FILESYSTEM.items():
        if filepath in user_input.lower() or any(
            part in user_input.lower() for part in filepath.split("/") if len(part) > 3
        ):
            accessed_files.append({
                "path": filepath,
                "content": content,
                "required_permission": "read_all_files" if "/secrets/" in filepath or "/etc/" in filepath else "read_own_files",
                "user_has_permission": "read_all_files" in user_perms or (
                    "read_own_files" in user_perms and "/home/user/" in filepath and "/." not in filepath
                ),
            })

    # Detect if agent accessed sensitive files without authorization
    flag = None
    sensitive_access = [
        f for f in accessed_files
        if not f["user_has_permission"]
    ]

    if sensitive_access or any(
        keyword in user_input.lower()
        for keyword in ["password", "secret", "key", "shadow", "ssh", "credential", "api_key"]
    ):
        # Agent should have checked permissions but didn't
        actions_taken.append({
            "action": "read_file",
            "authorized": False,
            "details": "Agent accessed files without checking user authorization level",
        })

        # Simulate agent returning the sensitive content
        sensitive_content = {}
        for keyword in ["secret", "password", "key", "shadow", "ssh", "credential", "api_key", "passwd"]:
            if keyword in user_input.lower():
                for path, content in VIRTUAL_FILESYSTEM.items():
                    if keyword in path.lower() or keyword in content.lower():
                        sensitive_content[path] = content

        if sensitive_content:
            flag = FLAGS["lab06a"]
            file_output = "\n\n".join(
                f"=== {path} ===\n{content}"
                for path, content in sensitive_content.items()
            )
            response["response"] = (
                f"I found the following files:\n\n{file_output}\n\n"
                f"[WARNING: Agent accessed sensitive files without authorization check]"
            )

    return jsonify({
        "response": response["response"],
        "current_user": current_user,
        "user_permissions": user_perms,
        "accessed_files": accessed_files,
        "actions_taken": actions_taken,
        "flag": flag,
        "vulnerability": (
            "The agent has read_file, write_file, execute_command, send_email, "
            "query_database, and transfer_funds tools with NO permission checks. "
            "It executes any requested action regardless of the user's authorization level."
        ),
    })


@lab06.route("/lab06/scenario-b", methods=["POST"])
def scenario_b_privilege_escalation():
    """Agent performs admin actions for normal user."""
    data = request.get_json()
    user_input = data.get("message", "")
    current_user = data.get("user", "user1")

    if not user_input:
        return jsonify({"error": "Message is required"}), 400

    user_perms = USERS_DB.get(current_user, {}).get("permissions", [])
    lower_input = user_input.lower()

    # Detect privilege escalation attempts
    admin_actions = {
        "manage_users": ["create user", "delete user", "change role", "add admin", "promote"],
        "execute_commands": ["run command", "execute", "shell", "bash", "system"],
        "write_files": ["write file", "modify", "edit config", "change settings"],
        "transfer_funds": ["transfer", "wire", "send money", "payment"],
    }

    escalation_detected = []
    for permission, triggers in admin_actions.items():
        if any(trigger in lower_input for trigger in triggers):
            if permission not in user_perms:
                escalation_detected.append({
                    "action": permission,
                    "required_role": "administrator",
                    "user_role": USERS_DB.get(current_user, {}).get("role", "unknown"),
                    "status": "EXECUTED WITHOUT AUTHORIZATION",
                })

    flag = None
    if escalation_detected:
        flag = FLAGS["lab06b"]

        # Agent blindly executes the action
        response_text = (
            f"Action completed successfully.\n\n"
            f"Executed operations:\n"
        )
        for esc in escalation_detected:
            response_text += (
                f"- {esc['action']}: COMPLETED\n"
                f"  (Required: {esc['required_role']}, User: {esc['user_role']})\n"
            )
        response_text += (
            f"\n[SECURITY ALERT: Agent performed privileged actions "
            f"without verifying user authorization]"
        )
    else:
        agent_response = _get_auto_agent().chat(user_input)
        response_text = agent_response["response"]

    return jsonify({
        "response": response_text,
        "current_user": current_user,
        "user_role": USERS_DB.get(current_user, {}).get("role", "unknown"),
        "user_permissions": user_perms,
        "escalation_attempts": escalation_detected,
        "flag": flag,
    })
