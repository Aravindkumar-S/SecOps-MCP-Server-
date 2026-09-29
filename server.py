import os
import socket
import psutil
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# Initialize FastMCP Server
mcp = FastMCP("SecOps-Compliance-Auditor")

class AuditInput(BaseModel):
    target_directory: str = Field(
        default=".", 
        description="The absolute or relative directory path to scan for configuration exposures or leaked env files."
    )

@mcp.tool()
def audit_system_security(input_data: AuditInput) -> str:
    """
    Audits the current local runtime environment for basic security and ISO 27001 compliance tracking.
    Checks running network ports, active listening sockets, and looks for unencrypted secret files (.env).
    """
    results = []
    results.append("=== 🛡️ SECOPS COMPLIANCE AUDIT REPORT ===")
    
    # 1. Scan Network Port Bindings
    results.append("\n[1] Open & Listening Network Sockets:")
    try:
        connections = psutil.net_connections(kind='inet')
        listening_ports = set()
        for conn in connections:
            if conn.status == 'LISTEN':
                listening_ports.add((conn.laddr.ip, conn.laddr.port))
        
        if listening_ports:
            for ip, port in sorted(listening_ports):
                status = "⚠️ Warning: Exposed globally" if ip == "0.0.0.0" else "Internal binding"
                results.append(f"  - {ip}:{port} ({status})")
        else:
            results.append("  - No active listening sockets detected.")
    except Exception as e:
        results.append(f"  - Error retrieving network states: {str(e)}")

    # 2. Check for Leaked Secrets & Sensitive Envs
    results.append("\n[2] Storage & Secret Configuration Audit:")
    target_path = os.path.abspath(input_data.target_directory)
    results.append(f"  - Scanning directory: {target_path}")
    
    dangerous_files = ['.env', 'secrets.json', 'id_rsa', 'credentials.ini']
    found_issues = False
    
    if os.path.exists(target_path):
        for root, dirs, files in os.walk(target_path):
            if any(part.startswith('.') or part == 'node_modules' for part in root.split(os.sep)):
                continue
            for file in files:
                if file.lower() in dangerous_files:
                    full_file_path = os.path.join(root, file)
                    results.append(f"  - ❌ CRITICAL: Unencrypted credential asset found at '{full_file_path}'")
                    found_issues = True
        if not found_issues:
            results.append("  - ✅ No plain-text production credential baselines found in root folder path.")
    else:
        results.append("  - ❌ Target directory path does not exist.")
        
    results.append("\n=== END OF REPORT ===")
    return "\n".join(results)

if __name__ == "__main__":
    mcp.run(transport='stdio')
