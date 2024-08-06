from flask import Flask, request, jsonify
import requests
import os

app = Flask(__name__)

# GPT-4 API settings
GPT_API_URL = 'https://api.openai.com/v1/engines/gpt-4/completions'
GPT_API_KEY = os.getenv('GPT_API_KEY')  

# VirusTotal API settings
VT_API_URL = 'https://www.virustotal.com/api/v3'
VT_API_KEY = os.getenv('VT_API_KEY')  

def summarize_with_gpt(text):
    headers = {
        'Authorization': f'Bearer {GPT_API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'prompt': f"Summarize the following cybersecurity report and provide relevant cybersecurity-related analysis:\n\n{text}",
        'max_tokens': 400,
        'temperature': 0.3
    }

    response = requests.post(GPT_API_URL, json=payload, headers=headers)
    result = response.json().get('choices', [{}])[0].get('text', 'No result')
    return result

@app.route('/vt/scan', methods=['POST'])
def vt_scan():
    data = request.json
    file_hash = data.get('fileHash', '')
    url = data.get('url', '')
    ip = data.get('ip', '')

    headers = {
        'x-apikey': VT_API_KEY
    }

    if file_hash:
        response = requests.get(f'{VT_API_URL}/files/{file_hash}', headers=headers)
    elif url:
        response = requests.get(f'{VT_API_URL}/urls/{url}', headers=headers)
    elif ip:
        response = requests.get(f'{VT_API_URL}/ips/{ip}', headers=headers)
    else:
        return jsonify({'error': 'No valid parameter provided'}), 400

    result = response.json()
    summary = summarize_with_gpt(str(result))
    return jsonify({'result': result, 'summary': summary})

@app.route('/vt/dns', methods=['POST'])
def vt_dns():
    data = request.json
    domain = data.get('domain', '')

    headers = {
        'x-apikey': VT_API_KEY
    }

    response = requests.get(f'{VT_API_URL}/domains/{domain}', headers=headers)
    result = response.json()
    summary = summarize_with_gpt(str(result))
    return jsonify({'result': result, 'summary': summary})

@app.route('/gpt', methods=['POST'])
def gpt_request():
    data = request.json
    prompt = data.get('text', '')

    headers = {
        'Authorization': f'Bearer {GPT_API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'prompt': prompt,
        'max_tokens': 150
    }

    response = requests.post(GPT_API_URL, json=payload, headers=headers)
    result = response.json().get('choices', [{}])[0].get('text', 'No result')
    return jsonify({'result': result})

if __name__ == '__main__':
    app.run(debug=True)
