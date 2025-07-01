# Logstash Filter Generator

A modern web application that uses AI (Google Gemini) to generate Logstash filter configurations for structured log parsing, optimized for Wazuh integration with comprehensive validation and conflict prevention.

## 🚀 Features

### Core Functionality
- **AI-Powered Filter Generation**: Uses Google Gemini to analyze log samples and generate appropriate Logstash filters
- **Dual Workflow Support**: 
  - **Manual Input**: Enter log source name and sample logs for TCP input configuration
  - **File Upload**: Upload log files for file-based input configuration
- **Real-time Testing**: Test generated filters with actual log samples before deployment
- **Configuration Backup**: Automatic backup of existing configurations before applying changes
- **Automatic Configuration Management**: Creates Logstash configs, updates pipelines.yml, and configures Wazuh integration

### Advanced Validation & Security
- **Interactive Log Source Selection**: Searchable dropdown with common log sources + automatic custom input
- **Port Conflict Prevention**: Real-time validation to prevent TCP port conflicts (5040-5100 range)
- **Config File Conflict Prevention**: Prevents overwriting existing configurations with similar names
- **Comprehensive Input Validation**: 
  - Log source names: lowercase, alphanumeric + underscore + hyphen, 2-100 chars
  - Reserved word protection: input, output, filter, logstash, opensearch, wazuh, ossec
  - Sample log validation: length and format checks
  - File type validation: CSV, LOG, JSON, TXT only
- **Environment-based Configuration**: All settings configurable via environment variables
- **Enhanced Error Handling**: Detailed error messages and logging

### Modern UI/UX
- **Responsive Design**: Bootstrap-based interface that works on all devices
- **Interactive Dropdown**: Type to search existing log sources or enter custom names
- **Real-time Validation**: Immediate feedback with visual indicators (green/red borders)
- **Loading States**: Professional loading indicators during operations
- **Error Display**: Clear, specific error messages for each validation rule
- **Automatic Lowercase Conversion**: All log source names automatically converted to lowercase

### Integration Features
- **Wazuh Integration**: Automatic insertion of localfile blocks into ossec.conf
- **OpenSearch Output**: Configured JSON output to OpenSearch with proper indexing
- **Service Management**: Automatic Logstash and Wazuh service restart after configuration
- **File Management**: Proper file permissions and ownership management

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- Logstash installed and configured
- Wazuh manager installed (for full integration)
- OpenSearch/Elasticsearch running
- Sudo access for Logstash and Wazuh service management

### Setup
1. Clone the repository:
```bash
git clone <repository-url>
cd logstash_config_generator
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set environment variables:
```bash
export GEMINI_API_KEY="your_gemini_api_key_here"
export SECRET_KEY="your_secret_key_here"
```

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | Required | Google Gemini API key (get from Google AI Studio) |
| `SECRET_KEY` | Auto-generated | Flask secret key |
| `LOGSTASH_CONFIG_DIR` | `/etc/logstash/conf.d` | Logstash configuration directory |
| `LOGSTASH_RELOAD_COMMAND` | `sudo systemctl restart logstash` | Command to reload Logstash |
| `LOGSTASH_BIN_PATH` | `/usr/share/logstash/bin/logstash` | Path to Logstash binary |
| `MAX_LOG_LINES` | `50` | Maximum number of log lines to process |
| `MAX_LOG_LINE_LENGTH` | `1000` | Maximum length per log line |
| `REQUEST_TIMEOUT` | `60` | Timeout for external commands |
| `BACKUP_DIR` | `./backups` | Directory for configuration backups |
| `LOG_FILES_DIR` | `/etc/logstash/log_files/` | Directory for uploaded log files |

## 🎯 Usage

### Basic Usage
1. Start the application:
```bash
python src/main.py
```

2. Open your browser to `http://localhost:5000`

### Manual Log Source Creation
1. **Log Source Name**: Type to search existing sources or enter a custom name
2. **TCP Port**: Enter a port between 5040-5100 (auto-assigned if left empty)
3. **Sample Logs**: Paste 3-10 log lines for AI analysis
4. **Generate Filter**: AI creates optimized Logstash filter
5. **Review & Apply**: Test the filter and apply to Logstash

### File Upload Workflow
1. **Log Source Name**: Same as manual workflow
2. **Upload File**: Select CSV, LOG, JSON, or TXT file
3. **Automatic Processing**: 
   - File uploaded to `/etc/logstash/log_files/`
   - Sample lines extracted for filter generation
   - AI generates appropriate filter
   - Configuration created with file input
4. **Apply Configuration**: Automatically applied to Logstash

### Validation Features
- **Real-time Port Validation**: Checks for port conflicts as you type
- **Config File Conflict Prevention**: Warns if log source name would create duplicate config
- **Input Sanitization**: Automatic lowercase conversion and character validation
- **Reserved Word Protection**: Prevents use of system-reserved terms

## 🔧 API Endpoints

### REST API
- `GET /api/used-ports` - Get list of currently used TCP ports
- `GET /api/existing-confs` - Get list of existing configuration files
- `POST /generate` - Generate filter from manual input
- `POST /apply` - Apply generated configuration
- `POST /upload` - Upload file and generate configuration

### Example API Usage
```bash
# Get used ports
curl http://localhost:5000/api/used-ports

# Get existing configs
curl http://localhost:5000/api/existing-confs

# Generate filter
curl -X POST http://localhost:5000/generate \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "log_source_name=my_app&http_port=5040&sample_logs=log line 1\nlog line 2"
```

## 📁 Project Structure

```
logstash_config_generator/
├── src/
│   ├── main.py              # Main Flask application
│   ├── templates/
│   │   └── index.html       # Web interface with interactive features
│   └── app.log              # Application logs
├── backups/                 # Configuration backups
├── custom_log_sources.txt   # Custom log source names
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🔒 Security Considerations

- **API Key Management**: Store `GEMINI_API_KEY` in environment variables, never in code
- **Input Validation**: All inputs are validated, sanitized, and converted to safe formats
- **File Permissions**: Automatic proper permissions and ownership management
- **Conflict Prevention**: Prevents accidental overwrites and port conflicts
- **Network Security**: Consider running behind a reverse proxy in production
- **Service Integration**: Secure integration with Logstash and Wazuh services

## 🐛 Troubleshooting

### Common Issues

1. **"GEMINI_API_KEY is not set"**
   - Set the environment variable: `export GEMINI_API_KEY="your_key"`
   - Get API key from [Google AI Studio](https://makersuite.google.com/app/apikey)

2. **"Port already in use"**
   - Choose a different port in the 5040-5100 range
   - Check existing configurations for port conflicts

3. **"Configuration already exists"**
   - Choose a different log source name
   - The system prevents overwriting existing configs

4. **"Permission denied" errors**
   - Ensure the application user has sudo access for Logstash/Wazuh commands
   - Check file permissions in Logstash configuration directory

5. **Filter generation fails**
   - Check the sample logs format
   - Ensure logs are representative of the actual log format
   - Review the error details in the test results

6. **Logstash reload fails**
   - Check Logstash service status: `sudo systemctl status logstash`
   - Review Logstash logs: `sudo journalctl -u logstash`

### Logs
Application logs are written to `app.log` in the project directory with detailed information about operations and errors.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Google Gemini API for AI-powered filter generation
- Bootstrap for the responsive UI framework
- Font Awesome for icons
- Wazuh for SIEM integration capabilities


