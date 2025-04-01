import os
import json
import csv
import re
import sqlite3
import spacy
from bs4 import BeautifulSoup
import pandas as pd

# Загрузка предобученной модели spaCy
try:
    nlp = spacy.load("en_core_web_sm")
except:
    from spacy.cli import download
    download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")

# Регулярные выражения
cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
phone_pattern = re.compile(r'\+?\d{1,3}[ -]?\(?\d{1,4}\)?[ -]?\d{1,4}[ -]?\d{1,9}')
url_pattern = re.compile(r'(?:https?|ftp)://[\w.-]+(?:\.[a-zA-Z]{2,6})?(?:/[\w./?=%&-]*)?|\b(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})(?:/[\w./?=%&-]*)?\b')
endpoint_pattern = re.compile(r'/[\w-]+(?:/[\w-]+)*')

def detect_file_format(file_path):
    """Определяет формат файла по расширению."""
    ext = os.path.splitext(file_path)[1].lower()
    return {'json': 'json', 'csv': 'csv', 'html': 'html', 'htm': 'html', 'txt': 'txt'}.get(ext, 'unknown')

def parse_text_with_spacy(text):
    """Использует spaCy для извлечения сущностей."""
    doc = nlp(text)
    entities = {
        'cve': [], 'ip': [], 'email': [], 'phone': [], 'url': [], 'endpoint': []
    }
    for ent in doc.ents:
        if ent.label_ in ['MISC', 'PRODUCT', 'ORG']:  # Можно кастомизировать
            if cve_pattern.match(ent.text):
                entities['cve'].append(ent.text)
        elif ent.label_ == 'GPE':
            if ip_pattern.match(ent.text):
                entities['ip'].append(ent.text)
        elif ent.label_ == 'PERSON':
            if email_pattern.match(ent.text):
                entities['email'].append(ent.text)
        elif ent.label_ == 'CARDINAL':
            if phone_pattern.match(ent.text):
                entities['phone'].append(ent.text)
    return entities

def parse_txt(file_path):
    """Парсит TXT с помощью регулярных выражений и spaCy."""
    data = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            parsed = {
                'cve': cve_pattern.findall(line),
                'ip': ip_pattern.findall(line),
                'email': email_pattern.findall(line),
                'phone': phone_pattern.findall(line),
                'url': url_pattern.findall(line),
                'endpoint': endpoint_pattern.findall(line)
            }
            spacy_parsed = parse_text_with_spacy(line)
            for key in parsed:
                parsed[key] = list(set(parsed[key] + spacy_parsed[key]))
            data.append(parsed)
    return data

def parse_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

def parse_csv(file_path):
    df = pd.read_csv(file_path)
    return df.to_dict(orient='records')

def parse_html(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        soup = BeautifulSoup(file, 'html.parser')
    return {'text': soup.get_text()}

def parse_file(file_path):
    format_type = detect_file_format(file_path)
    if format_type == 'txt':
        return parse_txt(file_path)
    elif format_type == 'json':
        return parse_json(file_path)
    elif format_type == 'csv':
        return parse_csv(file_path)
    elif format_type == 'html':
        return parse_html(file_path)
    else:
        return {'error': 'Unsupported file format'}

def parse_directory(directory_path):
    results = []
    for file_name in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file_name)
        if os.path.isfile(file_path):
            parsed_data = parse_file(file_path)
            if isinstance(parsed_data, list):
                for entry in parsed_data:
                    entry['file_name'] = file_name
                    results.append(entry)
    return results

def init_db(db_path="parsed_results.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT,
            cve TEXT,
            ip TEXT,
            email TEXT,
            phone TEXT,
            url TEXT,
            endpoint TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_to_db(data, db_path="parsed_results.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    for entry in data:
        cursor.execute('''
            INSERT INTO scan_results (file_name, cve, ip, email, phone, url, endpoint) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry.get('file_name', 'unknown'),
            ', '.join(entry.get('cve', [])),
            ', '.join(entry.get('ip', [])),
            ', '.join(entry.get('email', [])),
            ', '.join(entry.get('phone', [])),
            ', '.join(entry.get('url', [])),
            ', '.join(entry.get('endpoint', []))
        ))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    directory_path = "./scan_results"
    init_db()
    parsed_data = parse_directory(directory_path)
    save_to_db(parsed_data)
    print("Данные успешно сохранены в SQLite.")
