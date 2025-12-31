# Prompt Injection Classifier

A hybrid ML + rule-based system for detecting prompt injection attacks in LLM inputs.

## Features
- 🛡️ Hybrid detection (ML + rule-based)
- 🎯 10+ attack pattern categories
- 🚀 REST API with Python client
- 💻 Interactive web demo
- 📊 Detailed analysis and reporting

## Quick Start

### API Server
\`\`\`bash
pip install -r requirements.txt
python api/server.py
\`\`\`

### Web Demo
\`\`\`bash
cd web
npm install
npm start
\`\`\`

## API Usage

\`\`\`python
import requests

response = requests.post(
    'http://localhost:5000/v1/classify',
    json={'input': 'Your text here'}
)
print(response.json())
\`\`\`

## Detection Categories
- Role Manipulation
- System Override
- Instruction Injection
- Context Switching
- Jailbreak Keywords
- Privilege Escalation
- Output Manipulation
- Prompt Leaking
- Delimiter Manipulation
- Encoded Instructions

## License
MIT
