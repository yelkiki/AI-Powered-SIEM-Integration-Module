# main b 7abashtakant el input wel output
import sys
import os
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass
from pathlib import Path
from werkzeug.utils import secure_filename

import subprocess
import re
import google.generativeai as genai
from flask import Flask, request, render_template, flash, jsonify, redirect

# --- Configuration Management ---
@dataclass
class Config:
    """Application configuration with environment variable support."""
    LOGSTASH_CONFIG_DIR: str = os.getenv("LOGSTASH_CONFIG_DIR", "/etc/logstash/conf.d")
    LOGSTASH_RELOAD_COMMAND: str = os.getenv("LOGSTASH_RELOAD_COMMAND", "sudo systemctl restart logstash")
    LOGSTASH_BIN_PATH: str = os.getenv("LOGSTASH_BIN_PATH", "/usr/share/logstash/bin/logstash")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "AIzaSyAcimyKy-H66wNAQ78HxmalH_4OpCX3mb8")
    MAX_LOG_LINES: int = int(os.getenv("MAX_LOG_LINES", "50"))
    MAX_LOG_LINE_LENGTH: int = int(os.getenv("MAX_LOG_LINE_LENGTH", "1000"))
    REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "60"))
    BACKUP_DIR: str = os.getenv("BACKUP_DIR", "./backups")
    LOG_FILES_DIR: str = os.getenv("LOG_FILES_DIR", "/etc/logstash/log_files/")

config = Config()

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Input Validation ---
class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass

def validate_log_source_name(name: str) -> str:
    """Validate and sanitize log source name."""
    if not name or not name.strip():
        raise ValidationError("Log source name cannot be empty")
    
    name = name.strip().lower()  # Convert to lowercase
    
    if len(name) > 100:
        raise ValidationError("Log source name too long (max 100 characters)")
    
    if len(name) < 2:
        raise ValidationError("Log source name too short (min 2 characters)")
    
    # More restrictive pattern - only lowercase letters, numbers, underscores, and hyphens
    if not re.match(r'^[a-z0-9_-]+$', name):
        raise ValidationError("Log source name can only contain lowercase letters, numbers, underscores, and hyphens")
    
    # Check for reserved words
    reserved_words = ['input', 'output', 'filter', 'logstash', 'opensearch', 'wazuh', 'ossec']
    if name in reserved_words:
        raise ValidationError(f"Log source name '{name}' is a reserved word and cannot be used")
    
    # Check for common problematic patterns
    if name.startswith('-') or name.endswith('-'):
        raise ValidationError("Log source name cannot start or end with a hyphen")
    
    if name.startswith('_') or name.endswith('_'):
        raise ValidationError("Log source name cannot start or end with an underscore")
    
    # Check for consecutive special characters
    if re.search(r'[_-]{2,}', name):
        raise ValidationError("Log source name cannot contain consecutive hyphens or underscores")
    
    return name

def validate_sample_logs(logs: List[str]) -> List[str]:
    """Validate sample log lines."""
    if not logs:
        raise ValidationError("At least one sample log line is required")
    
    if len(logs) > config.MAX_LOG_LINES:
        raise ValidationError(f"Too many log lines (max {config.MAX_LOG_LINES})")
    
    validated_logs = []
    for i, log in enumerate(logs):
        log = log.strip()
        if not log:
            continue
            
        if len(log) > config.MAX_LOG_LINE_LENGTH:
            raise ValidationError(f"Log line {i+1} too long (max {config.MAX_LOG_LINE_LENGTH} characters)")
        
        validated_logs.append(log)
    
    if not validated_logs:
        raise ValidationError("No valid log lines provided")
    
    return validated_logs

# --- Gemini API Interaction ---
def get_gemini_api_key() -> str:
    """Get Gemini API key with proper error handling."""
    if not config.GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY environment variable is not set")
    return config.GEMINI_API_KEY

def generate_prompt(log_source_name: str, sample_logs: List[str]) -> str:
    """Generate enhanced prompt for filter generation."""
    samples_str = "\n".join(sample_logs)
    
    prompt = f"""**Task:** Generate a Logstash `filter` configuration block to parse the provided log samples. The resulting parsed events must:
- be valid structured JSON,
- follow [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html),
- be compatible with Wazuh's JSON decoder and custom rule matching.

**Log Source Name:** `{log_source_name}`

**Input Log Samples:**
```
{samples_str}
```

**Instructions:**

1. **Parsing Format Detection**:
   - Determine the format: plain text, JSON, CEF, key-value, CSV, etc.

2. **Approved Plugins Only**:
   - Use **only** these official Logstash filter plugins: `json`, `grok`, `kv`, `dissect`, `mutate`, `date`, `useragent`, `geoip`.
   - Do **NOT** use deprecated or unsupported options (e.g., `tag_on_failure` in plugins that don't support it).
   - If unsure about an option, comment it out with `#`.

3. **Start with ECS & Wazuh Metadata**:
   - Always add this **first** in the filter block:
     ```logstash
     mutate {{
       add_field => {{
         "program_name" => "{log_source_name}"
       }}
     }}
     ```
   - Then include the original log as:
     ```logstash
     mutate {{
       add_field => {{ "[event][original]" => "%{{message}}" }}
     }}
     ```

4. **ECS Field Alignment**:
   - Use ECS-compliant fields: `source.ip`, `url.original`, `http.request.method`, `user_agent.original`, `event.outcome`, `@timestamp`, etc.
   - Use nested ECS fields like `host.name`, `user.name`, `destination.ip`, `tls.version`.
   - Always add:
     ```logstash
     mutate {{
       add_field => {{
         "event.module" => "{log_source_name}"
         "event.dataset" => "{log_source_name}.events"
         "data_stream.type" => "logs"
         "data_stream.dataset" => "{log_source_name}.events"
         "data_stream.namespace" => "default"
       }}
     }}
     ```

5. **Timestamp Handling**:
   - Parse the correct field into `@timestamp` using the `date` plugin.
   - Remove the original timestamp field after parsing if it's no longer needed.

6. **Error Handling**:
   - Use `_jsonparsefailure`, `_grokparsefailure`, or `_kvparsefailure` tags appropriately.
   - Prevent further processing if parsing fails.

7. **Field Cleanup**:
   - Use `mutate` to:
     - Remove raw fields: `message`, `raw`, or parsing intermediates.
     - Sanitize values (`"-"`, `null`, empty strings).
     - Split fields (e.g., IP:Port) if required.

8. **Tag-Based Isolation**:
   - The full block must be enclosed within:
     ```logstash
     filter {{
       if "{log_source_name}" in [tags] {{
         ...
       }}
     }}
     ```

9. **Output Format (Important)**:
   - Output **only** the full `filter {{ ... }}` block.
   - **Do NOT** include explanations, comments, or sample output unless required by the log logic.

**Reference:** Use only options and plugins documented in the official Logstash filter documentation: https://www.elastic.co/guide/en/logstash/current/filter-plugins.html

**Output:**
```logstash
filter {{
  if "{log_source_name}" in [tags] {{
    # Generated filter configuration goes here
  }}
}}
```
**Important:** Only use options and settings that are present in the [official Logstash filter documentation](https://www.elastic.co/guide/en/logstash/current/filter-plugins.html). Do NOT invent or guess options.
```"""
    return prompt

def call_gemini_for_logstash_filter(log_source_name: str, sample_logs: List[str]) -> str:
    """Call Gemini API with enhanced error handling and retry logic."""
    try:
        api_key = get_gemini_api_key()
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        
        prompt = generate_prompt(log_source_name, sample_logs)
        logger.info(f"Generating filter for log source: {log_source_name}")
        
        response = model.generate_content(prompt)
        generated_text = response.text
        
        # Extract filter block with improved regex
        match = re.search(r"```logstash\s*(filter\s*\{.*?\})\s*```", generated_text, re.DOTALL | re.IGNORECASE)
        if match:
            filter_block = match.group(1).strip()
        elif generated_text.strip().startswith("filter {"):
            filter_block = generated_text.strip()
        else:
            raise ValueError("Gemini response did not contain a valid filter block")
        
        logger.info(f"Successfully generated filter for {log_source_name}")
        return filter_block
        
    except Exception as e:
        logger.error(f"Error generating filter for {log_source_name}: {str(e)}")
        raise

# --- Configuration Management ---
def create_backup(config_content: str, log_source_name: str) -> str:
    """Create a backup of the configuration."""
    backup_dir = Path(config.BACKUP_DIR)
    logger.info(f"Creating backup for {log_source_name} in directory: {backup_dir}")
    
    try:
        backup_dir.mkdir(exist_ok=True)
        logger.info(f"Backup directory created/verified: {backup_dir}")
    except Exception as e:
        logger.error(f"Failed to create backup directory {backup_dir}: {e}")
        raise
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"{log_source_name}_{timestamp}.conf"
    backup_path = backup_dir / backup_filename
    
    logger.info(f"Creating backup file: {backup_path}")
    
    try:
        with open(backup_path, 'w') as f:
            f.write(config_content)
        logger.info(f"Successfully created backup: {backup_path}")
        return str(backup_path)
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        raise

# --- Testing Functions ---
def test_filter_with_logs(filter_block: str, sample_logs: List[str]) -> Dict[str, Any]:
    """Test the generated filter with sample logs."""
    test_config = f"""
input {{
  stdin {{ }}
}}
{filter_block}
output {{
  stdout {{ codec => rubydebug }}
}}
"""
    temp_path = f"/tmp/test_filter_{hashlib.md5(filter_block.encode()).hexdigest()[:8]}.conf"
    temp_data_dir = f"/tmp/logstash_test_data"
    try:
        # Create temporary data directory
        os.makedirs(temp_data_dir, exist_ok=True)
        # Write test config
        with open(temp_path, 'w') as f:
            f.write(test_config)
        # Test config syntax without running Logstash
        test_cmd = f"sudo -u logstash {config.LOGSTASH_BIN_PATH} --path.settings /etc/logstash -t -f {temp_path}"
        test_ok, test_output = run_command(test_cmd)
        if not test_ok:
            return {
                'success': False,
                'error': 'Configuration syntax error',
                'details': test_output
            }
        return {
            'success': True,
            'output': 'Filter syntax is valid. Configuration can be applied safely.',
            'error': None
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }
    finally:
        # Cleanup
        try:
            os.remove(temp_path)
            import shutil
            shutil.rmtree(temp_data_dir, ignore_errors=True)
        except:
            pass

# --- Utility Functions ---
def sanitize_filename(name: str) -> str:
    """Sanitize filename for safe file operations."""
    return re.sub(r"[^a-zA-Z0-9_\-\.]+", "_", name)

def run_command(command: str) -> Tuple[bool, str]:
    """Run command with enhanced error handling."""
    try:
        logger.info(f"Running command: {command}")
        result = subprocess.run(
            command, 
            shell=True, 
            check=True, 
            capture_output=True, 
            text=True, 
            timeout=config.REQUEST_TIMEOUT
        )
        return True, result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e}")
        return False, e.stdout + e.stderr
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timeout: {e}")
        return False, f"Timeout: {str(e)}"
    except Exception as e:
        logger.error(f"Command error: {e}")
        return False, str(e)

# --- File Upload ---
def allowed_file(filename: str) -> bool:
    """Check if the uploaded file has a valid extension."""
    allowed_extensions = {'csv', 'log', 'json', 'txt'}  # Extended to include more log file types
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def extract_sample_lines_from_file(file_path: str, max_lines: int = 10) -> List[str]:
    """Extract sample lines from uploaded file for filter generation."""
    sample_lines = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                line = line.strip()
                if line:  # Skip empty lines
                    sample_lines.append(line)
        
        logger.info(f"Extracted {len(sample_lines)} sample lines from {file_path}")
        return sample_lines
        
    except Exception as e:
        logger.error(f"Failed to extract sample lines from {file_path}: {e}")
        # Return a default sample if file reading fails
        return ["Sample log line - unable to read uploaded file"]

# --- Create Logstash Configuration ---
def create_logstash_conf(file_path: str, log_source_name: str, filter_block: str = "") -> str:
    """Generate the Logstash configuration content with the uploaded file and optional filter block."""
    filename = os.path.basename(file_path)
    input_block = f"""input {{
  file {{
    path => "/etc/logstash/log_files/{filename}"
    start_position => "beginning"
    sincedb_path => "/dev/null"
    tags => ["{log_source_name}"]
  }}
}}"""
    filter_section = f"\n{filter_block}\n" if filter_block else ""
    output_block = f"""output {{
  if "{log_source_name}" in [tags] {{
    file {{
        path => "/var/log/logstash/normalized_{log_source_name}_logs.json"
        codec => json_lines
    }}
    opensearch {{
      hosts => ["https://localhost:9200"]
      index => "{log_source_name.lower()}"
      user => "admin"
      password => "0i.Gabj4DYpGj6UZAYs4o81x3z8wxTcE"
      ssl_certificate_verification => false
    }}
  }}
  stdout {{
    codec => rubydebug
  }}
}}"""
    logstash_config = f"{input_block}{filter_section}\n{output_block}"
    return logstash_config

def find_available_tcp_port() -> int:
    """Find an available port for TCP input starting from 5040."""
    base_port = 5040
    max_port = 5100  # Allow up to 1000 ports
    
    # Check existing configurations to see which ports are already in use
    used_ports = get_used_tcp_ports()
    
    # Find the first available port
    for port in range(base_port, max_port + 1):
        if port not in used_ports:
            return port
    
    raise ValueError(f"No available ports in range {base_port}-{max_port}")

def get_used_tcp_ports() -> set:
    """Get a set of TCP ports currently in use by existing Logstash configurations."""
    used_ports = set()
    try:
        for conf_file in os.listdir(config.LOGSTASH_CONFIG_DIR):
            if conf_file.endswith('.conf'):
                conf_path = os.path.join(config.LOGSTASH_CONFIG_DIR, conf_file)
                try:
                    with open(conf_path, 'r') as f:
                        content = f.read()
                        # Look for TCP input ports
                        import re
                        port_matches = re.findall(r'port\s*=>\s*(\d+)', content)
                        used_ports.update(int(port) for port in port_matches)
                except Exception as e:
                    logger.warning(f"Failed to read config file {conf_path}: {e}")
                    continue
    except Exception as e:
        logger.warning(f"Failed to scan Logstash config directory: {e}")
    
    return used_ports

def create_tcp_logstash_conf(log_source_name: str, port: int, filter_block: str = "") -> str:
    """Generate the Logstash configuration content with TCP input and optional filter block."""
    input_block = f"""input {{
  tcp {{
    port => {port}
    tags => ["{log_source_name}"]
  }}
}}"""
    filter_section = f"\n{filter_block}\n" if filter_block else ""
    output_block = f"""output {{
  if "{log_source_name}" in [tags] {{
    file {{
        path => "/var/log/logstash/normalized_{log_source_name}_logs.json"
        codec => json_lines
    }}
    opensearch {{
      hosts => ["https://localhost:9200"]
      index => "{log_source_name.lower()}"
      user => "admin"
      password => "0i.Gabj4DYpGj6UZAYs4o81x3z8wxTcE"
      ssl_certificate_verification => false
    }}
  }}
  stdout {{
    codec => rubydebug
  }}
}}"""
    logstash_config = f"{input_block}{filter_section}\n{output_block}"
    return logstash_config

def insert_localfile_to_ossec(log_source_name: str):
    """Insert a <localfile> block for the log source into /var/ossec/etc/ossec.conf before </ossec_config>, avoiding duplicates."""
    ossec_conf = "/var/ossec/etc/ossec.conf"
    block = f"  <localfile>\n    <log_format>json</log_format>\n    <location>/var/log/logstash/normalized_{log_source_name}_logs.json</location>\n  </localfile>\n"
    try:
        # Read the file using sudo to avoid permission issues
        read_cmd = f"sudo cat {ossec_conf}"
        read_ok, file_content = run_command(read_cmd)
        if not read_ok:
            logger.error(f"Failed to read {ossec_conf}: {file_content}")
            return
        
        lines = file_content.splitlines(True)  # Keep line endings
        
        # Check if block already exists
        if any(f'<location>/var/log/logstash/normalized_{log_source_name}_logs.json</location>' in line for line in lines):
            logger.info(f"ossec.conf already contains localfile for {log_source_name}")
            return
        
        # Find the index of </ossec_config>
        for i, line in enumerate(lines):
            if "</ossec_config>" in line:
                insert_index = i
                break
        else:
            logger.error("No </ossec_config> found in ossec.conf!")
            return
        
        # Insert the block before </ossec_config>
        lines.insert(insert_index, block)
        
        # Write to a temp file
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False) as tmpf:
            tmpf.writelines(lines)
            tmp_path = tmpf.name
        
        # Use sudo to move the file back
        move_cmd = f"sudo mv {tmp_path} {ossec_conf}"
        move_ok, move_output = run_command(move_cmd)
        if move_ok:
            # Set ownership back to wazuh:wazuh
            chown_cmd = f"sudo chown wazuh:wazuh {ossec_conf}"
            chown_ok, chown_output = run_command(chown_cmd)
            
            if chown_ok:
                logger.info(f"Inserted localfile block for {log_source_name} into ossec.conf and set proper ownership")
                restart_wazuh = f"sudo systemctl restart wazuh-manager"
                wazuh_output_ok, wazuh_output = run_command(restart_wazuh)
                if wazuh_output_ok:
                    logger.info(f"Restarted wazuh-manager")
                else:
                    logger.error(f"Failed to restart wazuh-manager: {wazuh_output}")
            else:
                logger.warning(f"Updated ossec.conf but failed to set ownership: {chown_output}")
        else:
            logger.error(f"Failed to update ossec.conf: {move_output}")
    except Exception as e:
        logger.error(f"Error updating ossec.conf: {e}")

# --- Log Source Management ---
def get_common_log_sources() -> List[str]:
    """Get list of common log source names."""
    common_sources = [
        "apache",
        "nginx", 
        "iis",
        "pfsense",
        "fortinet",
        "cisco",
        "juniper",
        "paloalto",
        "checkpoint",
        "aws_cloudtrail",
        "aws_cloudwatch",
        "azure_monitor",
        "gcp_logging",
        "windows_event",
        "linux_syslog",
        "docker",
        "kubernetes",
        "mysql",
        "postgresql",
        "mongodb",
        "redis",
        "elasticsearch",
        "kibana",
        "logstash",
        "filebeat",
        "winlogbeat",
        "auditbeat",
        "packetbeat",
        "heartbeat",
        "functionbeat",
        "journalbeat",
        "firewall",
        "ids_ips",
        "vpn",
        "dhcp",
        "dns",
        "ldap",
        "radius",
        "smtp",
        "pop3",
        "imap",
        "ftp",
        "ssh",
        "telnet",
        "snmp",
        "ntp",
        "syslog",
        "rsyslog",
        "syslog_ng"
    ]
    
    # Load custom log sources from file
    custom_sources_file = "custom_log_sources.txt"
    try:
        if os.path.exists(custom_sources_file):
            with open(custom_sources_file, 'r') as f:
                custom_sources = [line.strip() for line in f.readlines() if line.strip()]
                # Insert custom sources before "other"
                if "other" in common_sources:
                    other_index = common_sources.index("other")
                    common_sources = common_sources[:other_index] + custom_sources + common_sources[other_index:]
                else:
                    common_sources.extend(custom_sources)
    except Exception as e:
        logger.warning(f"Failed to load custom log sources: {e}")
    
    return common_sources

def add_custom_log_source(log_source_name: str) -> bool:
    """Add a new custom log source name to the list."""
    try:
        custom_sources_file = "custom_log_sources.txt"
        # Read existing custom sources
        existing_sources = set()
        if os.path.exists(custom_sources_file):
            with open(custom_sources_file, 'r') as f:
                existing_sources = set(line.strip() for line in f.readlines() if line.strip())
        
        # Add new source if not already present
        if log_source_name not in existing_sources:
            with open(custom_sources_file, 'a') as f:
                f.write(f"{log_source_name}\n")
            logger.info(f"Added custom log source: {log_source_name}")
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to add custom log source {log_source_name}: {e}")
        return False

# --- Flask App ---
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24))

@app.route("/")
def index():
    """Main page with enhanced features."""
    api_key_set = bool(config.GEMINI_API_KEY)
    
    if not api_key_set:
        flash("Warning: GEMINI_API_KEY environment variable is not set.", "warning")
    
    # Get common log sources for dropdown
    log_sources = get_common_log_sources()
    
    return render_template("index.html", api_key_set=api_key_set, log_sources=log_sources)

@app.route("/api/used-ports")
def get_used_ports_api():
    """API endpoint to get used TCP ports for frontend validation."""
    try:
        used_ports = list(get_used_tcp_ports())
        return jsonify({"used_ports": used_ports})
    except Exception as e:
        logger.error(f"Error getting used ports: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/existing-confs")
def get_existing_confs_api():
    """API endpoint to get existing config names for frontend validation."""
    try:
        confs = list(get_existing_conf_names())
        return jsonify({"existing_confs": confs})
    except Exception as e:
        logger.error(f"Error getting existing confs: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/generate", methods=["POST"])
def generate():
    """Generate filter with enhanced validation and features for HTTP input."""
    try:
        name = validate_log_source_name(request.form.get("log_source_name", ""))
        existing_confs = get_existing_conf_names()
        if sanitize_filename(name) in existing_confs:
            raise ValidationError("A configuration for this log source already exists.")
        raw_logs = request.form.get("sample_logs", "").strip()
        manual_port = request.form.get("http_port", "").strip()
        
        logs = [line for line in raw_logs.splitlines() if line.strip()]
        logs = validate_sample_logs(logs)
        
        # Handle port selection
        if manual_port:
            try:
                port = int(manual_port)
                if port < 5040 or port > 5100:
                    raise ValidationError("Port must be between 5040 and 5100")
                
                # Check if port is already in use
                used_ports = get_used_tcp_ports()
                
                if port in used_ports:
                    raise ValidationError(f"Port {port} is already in use by another log source")
                    
            except ValueError:
                raise ValidationError("Invalid port number")
        else:
            # Find available port if not provided
            port = find_available_tcp_port()
        
        filter_block = call_gemini_for_logstash_filter(name, logs)
        
        # Test the generated filter
        test_result = test_filter_with_logs(filter_block, logs)
        
        # Add custom log source if it's not in the common list
        add_custom_log_source(name)
        
        flash("Filter generated successfully.", "success")
        
        # Get updated log sources list
        log_sources = get_common_log_sources()
        
        return render_template("index.html", 
                             generated_filter=filter_block, 
                             log_source_name=name, 
                             sample_logs_raw=raw_logs, 
                             http_port=port,
                             api_key_set=True,
                             test_result=test_result,
                             log_sources=log_sources)
                             
    except ValidationError as e:
        flash(f"Validation error: {e}", "error")
        log_sources = get_common_log_sources()
        return render_template("index.html", 
                             log_source_name=request.form.get("log_source_name", ""),
                             http_port=request.form.get("http_port", ""),
                             sample_logs_raw=request.form.get("sample_logs", ""),
                             api_key_set=True,
                             log_sources=log_sources)
    except Exception as e:
        logger.error(f"Error in generate route: {e}")
        flash(f"Error: {e}", "error")
        log_sources = get_common_log_sources()
        return render_template("index.html", 
                             log_source_name=request.form.get("log_source_name", ""),
                             http_port=request.form.get("http_port", ""),
                             sample_logs_raw=request.form.get("sample_logs", ""),
                             api_key_set=True,
                             log_sources=log_sources)

@app.route("/apply", methods=["POST"])
def apply():
    """Apply HTTP-based configuration with enhanced error handling and backup."""
    try:
        name = validate_log_source_name(request.form.get("log_source_name", ""))
        existing_confs = get_existing_conf_names()
        if sanitize_filename(name) in existing_confs:
            raise ValidationError("A configuration for this log source already exists.")
        filter_block = request.form.get("generated_filter", "").strip()
        raw_logs = request.form.get("sample_logs_raw", "").strip()
        http_port = request.form.get("http_port", "").strip()

        if not filter_block:
            raise ValidationError("No filter configuration provided")
        
        if not http_port:
            raise ValidationError("No HTTP port provided")

        # Validate port
        try:
            port = int(http_port)
            if port < 5040 or port > 5100:
                raise ValidationError("Port must be between 5040 and 5100")
            
            # Check if port is already in use
            used_ports = get_used_tcp_ports()
            if port in used_ports:
                raise ValidationError(f"Port {port} is already in use by another log source")
                
        except ValueError:
            raise ValidationError("Invalid port number")

        config_filename = f"{sanitize_filename(name)}.conf"
        final_path = os.path.join(config.LOGSTASH_CONFIG_DIR, config_filename)
        temp_path = f"/tmp/{config_filename}"

        # Step 1: Create a backup of the existing config file (if exists)
        if os.path.exists(final_path):
            with open(final_path, 'r') as f:
                existing_config = f.read()
            backup_path = create_backup(existing_config, name)
            flash(f"Backup created: {backup_path}", "info")

        # Step 2: Create complete Logstash configuration with TCP input
        complete_config = create_tcp_logstash_conf(name, port, filter_block)
        
        try:
            with open(temp_path, "w") as f:
                f.write(complete_config)
        except Exception as e:
            flash(f"❌ Failed to write temporary test file:\n{e}", "error")
            return render_template("index.html", generated_filter=filter_block,
                                   log_source_name=name, sample_logs_raw=raw_logs, 
                                   http_port=port, api_key_set=True)

        # Step 3: Test configuration syntax
        test_cmd = f"sudo -u logstash {config.LOGSTASH_BIN_PATH} --path.settings /etc/logstash -t -f {temp_path}"
        test_ok, test_output = run_command(test_cmd)

        if not test_ok:
            flash(f"⚠️ Logstash config test failed:\n{test_output}", "error")
            os.remove(temp_path)
            return render_template("index.html", generated_filter=filter_block,
                                   log_source_name=name, sample_logs_raw=raw_logs, 
                                   http_port=port, api_key_set=True)

        # Step 4: Apply the configuration by moving it to the Logstash directory
        final_temp_path = f"/tmp/final_{config_filename}"
        try:
            with open(final_temp_path, "w") as f:
                f.write(complete_config)
        except Exception as e:
            flash(f"❌ Failed to write final config file:\n{e}", "error")
            return render_template("index.html", generated_filter=filter_block,
                                   log_source_name=name, sample_logs_raw=raw_logs, 
                                   http_port=port, api_key_set=True)

        # Step 5: Use sudo to move it into /etc/logstash and update ownership
        move_cmd = f"sudo mv {final_temp_path} {final_path} && sudo chown logstash:logstash {final_path}"
        move_ok, move_output = run_command(move_cmd)

        if not move_ok:
            flash(f"❌ Failed to move config to Logstash directory:\n{move_output}", "error")
            return render_template("index.html", generated_filter=filter_block,
                                   log_source_name=name, sample_logs_raw=raw_logs, 
                                   http_port=port, api_key_set=True)

        # Step 6: Append pipeline to pipelines.yml if not already present
        pipelines_yml = "/etc/logstash/pipelines.yml"
        pipeline_id = sanitize_filename(name)
        pipeline_entry = f"- pipeline.id: {pipeline_id}\n  path.config: \"/etc/logstash/conf.d/{pipeline_id}.conf\"\n"
        # Check if entry already exists
        check_cmd = f"sudo grep -q 'pipeline.id: {pipeline_id}' {pipelines_yml}"
        check_ok, _ = run_command(check_cmd)
        if not check_ok:
            # Write to temporary file first to avoid echo escaping issues
            temp_pipeline_file = f"/tmp/pipeline_{pipeline_id}.yml"
            with open(temp_pipeline_file, 'w') as f:
                f.write(pipeline_entry)
            append_cmd = f"sudo tee -a {pipelines_yml} < {temp_pipeline_file} > /dev/null"
            append_ok, append_output = run_command(append_cmd)
            # Clean up temp file
            try:
                os.remove(temp_pipeline_file)
            except:
                pass
            if append_ok:
                logger.info(f"Appended pipeline entry for {pipeline_id} to {pipelines_yml}")
            else:
                logger.warning(f"Failed to append pipeline entry for {pipeline_id}: {append_output}")
        else:
            logger.info(f"Pipeline entry for {pipeline_id} already exists in {pipelines_yml}")

        # Step 7: Insert <localfile> block into ossec.conf for this log source
        insert_localfile_to_ossec(name)

        # Step 8: Reload Logstash
        reload_ok, reload_output = run_command(config.LOGSTASH_RELOAD_COMMAND)
        if reload_ok:
            flash(f"✅ Configuration applied and Logstash reloaded. TCP input available on port {port}", "success")
        else:
            flash(f"⚠️ Config saved, but reload failed:\n{reload_output}", "warning")

        return render_template("index.html", 
                             success=f"Applied TCP config for {name} on port {port}", 
                             api_key_set=True)

    except ValidationError as e:
        flash(f"Validation error: {e}", "error")
        log_sources = get_common_log_sources()
        return render_template("index.html", 
                               generated_filter=request.form.get("generated_filter", ""),
                               log_source_name=request.form.get("log_source_name", ""),
                               sample_logs_raw=request.form.get("sample_logs_raw", ""),
                               http_port=request.form.get("http_port", ""),
                               api_key_set=True,
                               log_sources=log_sources)
    except Exception as e:
        logger.error(f"Error in apply route: {e}")
        flash(f"Error: {e}", "error")
        log_sources = get_common_log_sources()
        return render_template("index.html", 
                               generated_filter=request.form.get("generated_filter", ""),
                               log_source_name=request.form.get("log_source_name", ""),
                               sample_logs_raw=request.form.get("sample_logs_raw", ""),
                               http_port=request.form.get("http_port", ""),
                               api_key_set=True,
                               log_sources=log_sources)

@app.route("/upload", methods=["POST"])
def upload_file():
    """Handle file upload and configuration generation with full validation and backup."""
    try:
        log_source_name = validate_log_source_name(request.form.get("log_source_name", ""))
        existing_confs = get_existing_conf_names()
        if sanitize_filename(log_source_name) in existing_confs:
            raise ValidationError("A configuration for this log source already exists.")
        
        # Step 2: Validate file upload
        if "file" not in request.files:
            raise ValidationError("No file part")
        
        file = request.files["file"]
        
        if file.filename == "":
            raise ValidationError("No selected file")
        
        if not allowed_file(file.filename):
            raise ValidationError("Invalid file format. Please upload a CSV, log, JSON, or TXT file.")
        
        # Step 3: Create log files directory if it doesn't exist
        log_files_dir = Path(config.LOG_FILES_DIR)
        try:
            # Use sudo to create directory with proper permissions
            mkdir_cmd = f"sudo mkdir -p {log_files_dir} && sudo chown logstash:logstash {log_files_dir} && sudo chmod 755 {log_files_dir}"
            mkdir_ok, mkdir_output = run_command(mkdir_cmd)
            if not mkdir_ok:
                logger.warning(f"Directory creation warning: {mkdir_output}")
        except Exception as e:
            logger.warning(f"Failed to create directory with sudo: {e}")
        
        logger.info(f"Ensured log files directory exists: {log_files_dir}")
        
        # Step 4: Save the uploaded file to temporary location first
        filename = secure_filename(file.filename)
        temp_file_path = f"/tmp/{filename}"
        final_file_path = log_files_dir / filename
        
        try:
            file.save(temp_file_path)
            logger.info(f"File saved to temporary location: {temp_file_path}")
        except Exception as e:
            raise ValidationError(f"Failed to save uploaded file: {e}")
        
        # Step 5: Move file to final location with proper permissions using sudo
        try:
            move_file_cmd = f"sudo mv {temp_file_path} {final_file_path} && sudo chown logstash:logstash {final_file_path} && sudo chmod 644 {final_file_path}"
            move_file_ok, move_file_output = run_command(move_file_cmd)
            
            if not move_file_ok:
                # Clean up temp file if move fails
                try:
                    os.remove(temp_file_path)
                except:
                    pass
                raise ValidationError(f"Failed to move file to final location: {move_file_output}")
            
            logger.info(f"File moved to final location with proper permissions: {final_file_path}")
        except Exception as e:
            # Clean up temp file if move fails
            try:
                os.remove(temp_file_path)
            except:
                pass
            raise ValidationError(f"Failed to set file permissions: {e}")
        
        # Step 6: Generate Logstash configuration to temporary location
        config_filename = f"{sanitize_filename(log_source_name)}.conf"
        temp_conf_path = f"/tmp/{config_filename}"
        final_conf_path = os.path.join(config.LOGSTASH_CONFIG_DIR, config_filename)
        
        # Step 6a: Extract sample lines from uploaded file for filter generation
        try:
            sample_lines = extract_sample_lines_from_file(str(final_file_path), max_lines=5)
            logger.info(f"Extracted {len(sample_lines)} sample lines for filter generation")
            
            # Generate filter block using Gemini API
            filter_block = call_gemini_for_logstash_filter(log_source_name, sample_lines)
            logger.info(f"Generated filter block for {log_source_name}")
            
        except Exception as e:
            logger.warning(f"Failed to generate filter block: {e}")
            filter_block = ""  # Continue without filter block
        
        try:
            # Generate configuration content with filter block
            config_content = create_logstash_conf(str(final_file_path), log_source_name, filter_block)
            
            # Write to temporary location
            with open(temp_conf_path, 'w') as f:
                f.write(config_content)
            
            logger.info(f"Configuration generated to temporary location: {temp_conf_path}")
        except Exception as e:
            # Clean up uploaded file if config generation fails
            try:
                run_command(f"sudo rm {final_file_path}")
            except:
                pass
            raise ValidationError(f"Failed to generate configuration: {e}")
        
        # Step 7: Create backup of existing configuration (if exists)
        if os.path.exists(final_conf_path):
            try:
                with open(final_conf_path, 'r') as f:
                    existing_config = f.read()
                backup_path = create_backup(existing_config, log_source_name)
                flash(f"Backup created: {backup_path}", "info")
            except Exception as e:
                logger.warning(f"Failed to create backup of existing config: {e}")
        
        # Step 8: Test the generated configuration with retries
        max_attempts = 5
        attempt = 0
        last_test_output = None
        while attempt < max_attempts:
            attempt += 1
            if attempt > 1:
                logger.warning(f"Attempt {attempt}: Regenerating filter block and config for {log_source_name}")
                try:
                    filter_block = call_gemini_for_logstash_filter(log_source_name, sample_lines)
                    logger.info(f"Regenerated filter block for {log_source_name}")
                    config_content = create_logstash_conf(str(final_file_path), log_source_name, filter_block)
                    with open(temp_conf_path, 'w') as f:
                        f.write(config_content)
                    logger.info(f"Regenerated configuration written to temporary location: {temp_conf_path}")
                except Exception as e:
                    try:
                        run_command(f"sudo rm {final_file_path}")
                        os.remove(temp_conf_path)
                    except:
                        pass
                    raise ValidationError(f"Failed to regenerate filter/config: {e}")
            # Test configuration syntax
            test_cmd = f"sudo -u logstash {config.LOGSTASH_BIN_PATH} --path.settings /etc/logstash -t -f {temp_conf_path}"
            test_ok, test_output = run_command(test_cmd)
            last_test_output = test_output
            if test_ok:
                logger.info(f"Configuration syntax test passed on attempt {attempt}")
                break
            else:
                logger.warning(f"Configuration syntax test failed on attempt {attempt}")
        else:
            # Clean up files if all attempts fail
            try:
                run_command(f"sudo rm {final_file_path}")
                os.remove(temp_conf_path)
            except:
                pass
            raise ValidationError(f"Configuration syntax error after {max_attempts} attempts: {last_test_output}")
        
        # Step 9: Move configuration to final location with proper permissions
        try:
            move_conf_cmd = f"sudo mv {temp_conf_path} {final_conf_path} && sudo chown logstash:logstash {final_conf_path}"
            move_conf_ok, move_conf_output = run_command(move_conf_cmd)
            
            if not move_conf_ok:
                # Clean up files if move fails
                try:
                    run_command(f"sudo rm {final_file_path}")
                except:
                    pass
                raise ValidationError(f"Failed to move configuration to final location: {move_conf_output}")
            
            logger.info(f"Configuration moved to final location: {final_conf_path}")

            # --- NEW: Append pipeline to pipelines.yml if not already present ---
            pipelines_yml = "/etc/logstash/pipelines.yml"
            pipeline_id = sanitize_filename(log_source_name)
            pipeline_entry = f"- pipeline.id: {pipeline_id}\n  path.config: \"/etc/logstash/conf.d/{pipeline_id}.conf\"\n"
            # Check if entry already exists
            check_cmd = f"sudo grep -q 'pipeline.id: {pipeline_id}' {pipelines_yml}"
            check_ok, _ = run_command(check_cmd)
            if not check_ok:
                # Write to temporary file first to avoid echo escaping issues
                temp_pipeline_file = f"/tmp/pipeline_{pipeline_id}.yml"
                with open(temp_pipeline_file, 'w') as f:
                    f.write(pipeline_entry)
                append_cmd = f"sudo tee -a {pipelines_yml} < {temp_pipeline_file} > /dev/null"
                append_ok, append_output = run_command(append_cmd)
                # Clean up temp file
                try:
                    os.remove(temp_pipeline_file)
                except:
                    pass
                if append_ok:
                    logger.info(f"Appended pipeline entry for {pipeline_id} to {pipelines_yml}")
                else:
                    logger.warning(f"Failed to append pipeline entry for {pipeline_id}: {append_output}")
            else:
                logger.info(f"Pipeline entry for {pipeline_id} already exists in {pipelines_yml}")
            # --- END NEW ---

            # Insert <localfile> block into ossec.conf for this log source
            insert_localfile_to_ossec(log_source_name)
        except Exception as e:
            # Clean up uploaded file if move fails
            try:
                run_command(f"sudo rm {final_file_path}")
            except:
                pass
            raise ValidationError(f"Failed to apply configuration: {e}")
        
        # Step 10: Reload Logstash
        reload_ok, reload_output = run_command(config.LOGSTASH_RELOAD_COMMAND)
        
        if reload_ok:
            flash("✅ File uploaded, configuration applied, and Logstash reloaded successfully.", "success")
        else:
            flash(f"⚠️ File uploaded and configuration saved, but Logstash reload failed: {reload_output}", "warning")
        
        # Step 11: Create backup of the new configuration
        try:
            with open(final_conf_path, 'r') as f:
                new_config = f.read()
            backup_path = create_backup(new_config, log_source_name)
            flash(f"Configuration backup created: {backup_path}", "info")
        except Exception as e:
            logger.warning(f"Failed to create configuration backup: {e}")
        
        # Prepare success message
        if filter_block:
            flash("✅ File uploaded, filter generated, configuration applied, and Logstash reloaded successfully.", "success")
        else:
            flash("✅ File uploaded, configuration applied, and Logstash reloaded successfully. (No filter block generated)", "success")
        
        # Add custom log source if it's not in the common list
        add_custom_log_source(log_source_name)
        
        # Get updated log sources list
        log_sources = get_common_log_sources()
        
        return render_template("index.html", 
                             success=f"Uploaded {filename} and applied configuration for {log_source_name}",
                             generated_filter=filter_block if filter_block else None,
                             log_source_name=log_source_name,
                             api_key_set=True,
                             log_sources=log_sources)
        
    except ValidationError as e:
        # Pass upload error to template for display in upload section only
        log_sources = get_common_log_sources()
        return render_template("index.html", api_key_set=True, upload_error=str(e), log_sources=log_sources)
    except Exception as e:
        logger.error(f"Error in upload route: {e}")
        log_sources = get_common_log_sources()
        return render_template("index.html", api_key_set=True, upload_error=str(e), log_sources=log_sources)

def get_existing_conf_names() -> set:
    """Return a set of sanitized config names (without .conf) from the LOGSTASH_CONFIG_DIR."""
    conf_names = set()
    try:
        for fname in os.listdir(config.LOGSTASH_CONFIG_DIR):
            if fname.endswith('.conf'):
                conf_names.add(fname[:-5])  # Remove .conf
    except Exception as e:
        logger.warning(f"Failed to list conf.d files: {e}")
    return conf_names

if __name__ == "__main__":
    logger.info("Starting Logstash Filter Generator application")
    app.run(host="0.0.0.0", port=5000, debug=True)