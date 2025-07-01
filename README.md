# Logstash Filter Generator

A modern web application that uses AI (Google Gemini) to generate Logstash filter configurations for structured log parsing, optimized for Wazuh integration.

## 🚀 Features

### Core Functionality
- **AI-Powered Filter Generation**: Uses Google Gemini to analyze log samples and generate appropriate Logstash filters
- **Template System**: Pre-built templates for common log formats (Apache, Nginx, Syslog, JSON)
- **Real-time Testing**: Test generated filters with actual log samples before deployment
- **Configuration Backup**: Automatic backup of existing configurations before applying changes
- **Configuration History**: Track and view previous configurations for each log source

### Security & Reliability
- **Input Validation**: Comprehensive validation for log source names and sample logs
- **Environment-based Configuration**: All settings configurable via environment variables
- **Enhanced Error Handling**: Detailed error messages and logging
- **Rate Limiting**: Configurable limits on log lines and line length

### Modern UI
- **Responsive Design**: Bootstrap-based interface that works on all devices
- **Real-time Feedback**: Loading indicators and test results display
- **Template Selection**: Dropdown with template descriptions and categories
- **Configuration History**: Visual timeline of previous configurations

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- Logstash installed and configured
- Sudo access for Logstash service management

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
| `GEMINI_API_KEY` | Required | Google Gemini API key |
| `SECRET_KEY` | Auto-generated | Flask secret key |
| `LOGSTASH_CONFIG_DIR` | `/etc/logstash/conf.d` | Logstash configuration directory |
| `LOGSTASH_RELOAD_COMMAND` | `sudo systemctl restart logstash` | Command to reload Logstash |
| `LOGSTASH_BIN_PATH` | `/usr/share/logstash/bin/logstash` | Path to Logstash binary |
| `MAX_LOG_LINES` | `50` | Maximum number of log lines to process |
| `MAX_LOG_LINE_LENGTH` | `1000` | Maximum length per log line |
| `REQUEST_TIMEOUT` | `60` | Timeout for external commands |
| `BACKUP_DIR` | `./backups` | Directory for configuration backups |
| `TEMPLATES_DIR` | `./templates/filter_templates` | Directory for filter templates |

## 🎯 Usage

### Basic Usage
1. Start the application:
```bash
python src/main.py
```

2. Open your browser to `http://localhost:5000`

3. Enter a log source name and paste sample log lines

4. Optionally select a template for consistent formatting

5. Click "Generate Filter" to create a Logstash filter

6. Review the generated filter and test results

7. Click "Save & Reload Logstash" to apply the configuration

### Templates

The application includes pre-built templates for common log formats:

- **Apache**: Web server logs (Common Log Format, Combined Log Format)
- **Nginx**: Web server access logs
- **Syslog**: RFC3164 and RFC5424 syslog messages
- **JSON**: Structured JSON log formats

### Testing Filters

The application automatically tests generated filters with your sample logs and displays:
- Syntax validation results
- Parsing output with extracted fields
- Error details if the filter fails

## 🔧 API Endpoints

### REST API
- `GET /api/templates` - Get available filter templates
- `POST /api/test` - Test a filter with sample logs
- `GET /api/history/<log_source_name>` - Get configuration history

### Example API Usage
```bash
# Test a filter
curl -X POST http://localhost:5000/api/test \
  -H "Content-Type: application/json" \
  -d '{
    "filter_block": "filter { ... }",
    "sample_logs": ["log line 1", "log line 2"]
  }'

# Get templates
curl http://localhost:5000/api/templates

# Get history
curl http://localhost:5000/api/history/my_log_source
```

## 📁 Project Structure

```
logstash_config_generator/
├── src/
│   ├── main.py              # Main application
│   ├── templates/
│   │   └── index.html       # Web interface
│   └── static/              # Static assets
├── templates/
│   └── filter_templates/    # Filter templates
│       ├── apache.yaml
│       ├── nginx.yaml
│       ├── syslog.yaml
│       └── json.yaml
├── backups/                 # Configuration backups
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🔒 Security Considerations

- **API Key Management**: Store `GEMINI_API_KEY` in environment variables, never in code
- **Input Validation**: All inputs are validated and sanitized
- **File Permissions**: Ensure proper permissions for Logstash configuration directory
- **Network Security**: Consider running behind a reverse proxy in production

## 🐛 Troubleshooting

### Common Issues

1. **"GEMINI_API_KEY is not set"**
   - Set the environment variable: `export GEMINI_API_KEY="your_key"`

2. **"Permission denied" errors**
   - Ensure the application user has sudo access for Logstash commands
   - Check file permissions in Logstash configuration directory

3. **Filter generation fails**
   - Check the sample logs format
   - Try using a template for common log formats
   - Review the error details in the test results

4. **Logstash reload fails**
   - Check Logstash service status: `sudo systemctl status logstash`
   - Review Logstash logs: `sudo journalctl -u logstash`

### Logs
Application logs are written to `app.log` in the project directory.

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
- The Logstash community for filter patterns and best practices


