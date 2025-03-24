import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from flask import Flask, request, jsonify, render_template_string
from ldap3 import Server, Connection, ALL, MODIFY_ADD, MODIFY_REPLACE, Tls
import threading
import json
import os
import ssl
from datetime import datetime
from cryptography.fernet import Fernet
import subprocess

# Flask uygulaması
app = Flask(__name__)

# Dosya tanımlamaları
CONFIG_FILE = 'config.txt'
LOG_FILE = 'service.log'
KEY_FILE = 'secret.key'
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5000

# Şifreleme anahtarı
def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    with open(KEY_FILE, 'rb') as f:
        return f.read()

cipher = Fernet(load_or_create_key())

# Default config
default_config = {
    "ad_server": "ldaps://dc01.server.local",
    "ad_user": "administrator@server.local",
    "ad_password": "your_ad_password",
    "search_base": "DC=SERVER,DC=LOCAL",
    "tokens": [
        "your_token1",
        "your_token2"
    ],
    "include_list": [
        "OU=SERVER_OU,DC=SERVER,DC=LOCAL"
    ],
    "exclude_list": [
        "CN=Administrators,CN=Builtin,DC=SERVER,DC=LOCAL",
        "OU=EXCLUDE,OU=SERVER_OU,DC=SERVER,DC=LOCAL"
    ]
}

# Config dosyası yoksa oluştur
if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(default_config, f, indent=4)
    root = tk.Tk()
    root.withdraw()
    messagebox.showwarning(
        "Config Dosyası Oluşturuldu",
        "config.txt dosyası oluşturuldu. Lütfen bilgileri güncelleyip programı yeniden çalıştırın."
    )
    if os.name == 'nt':
        os.startfile(CONFIG_FILE)
    elif os.name == 'posix':
        subprocess.call(['xdg-open', CONFIG_FILE])
    root.destroy()
    exit(0)

# Config dosyasını oku
with open(CONFIG_FILE, 'r') as f:
    config_data = json.load(f)

# Şifreyi şifrele ve kaydet
def encrypt_and_save_password(password):
    encrypted_password = cipher.encrypt(password.encode()).decode()
    config_data['ad_password'] = encrypted_password
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_data, f, indent=4)

# Şifreyi çöz
def decrypt_password(encrypted_password):
    try:
        return cipher.decrypt(encrypted_password.encode()).decode()
    except Exception:
        return None

# LDAP bağlantı testi
def test_ldap_connection(ad_server, ad_user, ad_password):
    try:
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(ad_server, port=636, use_ssl=True, tls=tls_config, get_info=ALL)
        conn = Connection(server, ad_user, ad_password, auto_bind=True)
        conn.unbind()
        return True
    except Exception as e:
        log_to_file(f"LDAP bağlantı hatası: {e}")
        return False

# İlk açılışta şifre kontrolü
def check_and_update_password():
    ad_password = config_data['ad_password']
    if decrypt_password(ad_password) is None:
        root = tk.Tk()
        root.withdraw()
        while True:
            password = simpledialog.askstring("LDAP Şifresi", "LDAP şifrenizi girin:", show='*', parent=root)
            if password is None:
                messagebox.showinfo("İptal Edildi", "Şifre girişi iptal edildi, program kapanıyor.", parent=root)
                root.destroy()
                exit(0)
            if password and test_ldap_connection(config_data['ad_server'], config_data['ad_user'], password):
                encrypt_and_save_password(password)
                messagebox.showinfo("Başarılı", "Şifre doğrulandı ve şifrelendi!", parent=root)
                root.destroy()
                break
            else:
                messagebox.showerror("Hata", "Geçersiz şifre! Tekrar deneyin.", parent=root)
    else:
        decrypted_password = decrypt_password(ad_password)
        if not test_ldap_connection(config_data['ad_server'], config_data['ad_user'], decrypted_password):
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Hata", "Şifrelenmiş şifre geçersiz! Config dosyasını kontrol edin.", parent=root)
            root.destroy()
            exit(1)

# Log dosyasına yazma
def log_to_file(message, username=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = username if username is not None else "Sistem"
    try:
        if hasattr(request, 'method') and request.method == 'POST' and request.content_type == 'application/json':
            json_data = request.get_json(silent=True)
            if json_data and 'postuser' in json_data:
                user = json_data['postuser']
            elif not username:
                user = request.remote_addr
    except RuntimeError:
        pass
    
    log_message = f"[{timestamp}] [Kullanıcı: {user}] {message}"
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_message + "\n")
    except Exception as e:
        print(f"Log dosyasına yazma hatası: {e}, Dosya: {LOG_FILE}")

# Özet ekranına yazma
def summary_output(message):
    output_text.insert(tk.END, f"{message}\n")
    output_text.see(tk.END)

# XML formatına çevirme (kullanıcı listesi için)
def to_xml(users):
    import xml.etree.ElementTree as ET
    root = ET.Element("users")
    for user in users:
        user_elem = ET.SubElement(root, "user")
        for key, value in user.items():
            child = ET.SubElement(user_elem, key)
            child.text = str(value) if value else ""
    return ET.tostring(root, encoding='unicode', method='xml')

# Token doğrulama
def verify_token(request_data):
    provided_token = request_data.get('token')
    if not provided_token or provided_token not in config_data['tokens']:
        log_to_file("Geçersiz veya eksik token!")
        summary_output("Geçersiz token denemesi!")
        return False
    return True

# Endpoint'ler
@app.route('/addContact', methods=['POST'])
def add_contact():
    data = request.get_json(silent=True)
    postuser = data.get('postuser') if data else None
    log_to_file("addContact endpoint'ine istek geldi.", username=postuser)
    summary_output("addContact: İstek alındı")
    try:
        if data is None:
            log_to_file("Gelen veri None! JSON formatı geçersiz.", username=postuser)
            return jsonify({'message': 'Invalid JSON data!', 'status': 'error'}), 400
        log_to_file(f"Gelen Veri: {json.dumps(data, indent=4)}", username=postuser)
        
        if not verify_token(data):
            return jsonify({'message': 'Invalid or missing token!', 'status': 'invalid_token'}), 403
        
        first_name = data.get('first_name')
        display_name = data.get('display_name')
        description = data.get('description')
        email = data.get('email')
        job_title = data.get('job_title')
        department = data.get('department')
        company = data.get('company')
        member_of = data.get('member_of', [])  # group_name yerine member_of listesi
        create_ou_path = data.get('create_ou_path')
        
        required_fields = {'first_name': first_name, 'display_name': display_name, 'create_ou_path': create_ou_path}
        missing_fields = [field for field, value in required_fields.items() if not value]
        if missing_fields:
            log_to_file(f"Eksik parametreler: {', '.join(missing_fields)}", username=postuser)
            summary_output("addContact: Eksik parametre")
            return jsonify({'message': f"Missing required fields: {', '.join(missing_fields)}", 'status': 'missing_parameters'}), 400
        
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(config_data['ad_server'], port=636, use_ssl=True, tls=tls_config, get_info=ALL)
        conn = Connection(server, config_data['ad_user'], decrypt_password(config_data['ad_password']), auto_bind=True)
        log_to_file("LDAPS bağlantısı başarılı!", username=postuser)
        summary_output("addContact: Bağlantı başarılı")
        
        contact_dn = f'CN={display_name},{create_ou_path}'
        conn.add(contact_dn, ['top', 'contact'], {
            'givenName': first_name,
            'displayName': display_name,
            'description': description,
            'mail': email,
            'title': job_title,
            'department': department,
            'company': company
        })
        
        if conn.result['description'] != 'success':
            log_to_file(f"Kişi ekleme hatası: {conn.result}", username=postuser)
            summary_output("addContact: Kişi ekleme başarısız")
            conn.unbind()
            return jsonify({'message': conn.result['description'], 'status': 'error'}), 400
        
        log_to_file("Kişi başarıyla eklendi!", username=postuser)
        
        if member_of:
            for group in member_of:
                group_dn = f'{group}'
                conn.modify(group_dn, {'member': [(MODIFY_ADD, [contact_dn])]})
                if conn.result['description'] != 'success':
                    log_to_file(f"Gruba ekleme hatası ({group}): {conn.result}", username=postuser)
                    summary_output(f"addContact: {group} grubuna ekleme başarısız")
                    conn.unbind()
                    return jsonify({'message': f'Failed to add contact to group {group}: {conn.result["description"]}', 'status': 'error'}), 400
                log_to_file(f"Kişi {group} grubuna eklendi!", username=postuser)
        
        summary_output(f"addContact: {display_name} oluşturuldu ve gruplara eklendi")
        conn.unbind()
        return jsonify({'message': f'Contact {display_name} created and added to groups successfully!', 'status': 'success'}), 201
    
    except Exception as e:
        log_to_file(f"addContact hatası: {str(e)}", username=postuser)
        summary_output("addContact: Hata oluştu")
        if 'conn' in locals():
            conn.unbind()
        return jsonify({'message': f'Error: {str(e)}', 'status': 'error'}), 500

@app.route('/getUserList', methods=['POST'])
def get_user_list():
    data = request.get_json(silent=True)
    postuser = data.get('postuser') if data else None
    log_to_file("getUserList endpoint'ine istek geldi.", username=postuser)
    summary_output("getUserList: İstek alındı")
    
    try:
        if data is None:
            log_to_file("Gelen veri None! JSON formatı geçersiz.", username=postuser)
            return jsonify({'message': 'Invalid JSON data!', 'status': 'error'}), 400
        log_to_file(f"Gelen Veri: {json.dumps(data, indent=4)}", username=postuser)
        
        if not verify_token(data):
            return jsonify({'message': 'Invalid or missing token!', 'status': 'invalid_token'}), 403
        
        response_format = data.get('format', 'json')
        
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(config_data['ad_server'], port=636, use_ssl=True, tls=tls_config, get_info=ALL)
        conn = Connection(server, config_data['ad_user'], decrypt_password(config_data['ad_password']), auto_bind=True)
        log_to_file("LDAPS bağlantısı başarılı!", username=postuser)
        summary_output("getUserList: Bağlantı başarılı")
        
        include_filter = ''.join(f'(memberOf={dn})' for dn in config_data['include_list'])
        exclude_filter = ''.join(f'(!(memberOf={dn}))' for dn in config_data['exclude_list'])
        search_filter = (
            f'(&(objectClass=user)'
            f'{include_filter}'
            f'{exclude_filter}'
            f'(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        )
        attributes = ['cn', 'mail', 'sAMAccountName', 'title']
        log_to_file(f"LDAP Search Filter: {search_filter}", username=postuser)
        log_to_file(f"Search Base: {config_data['search_base']}", username=postuser)
        
        conn.search(config_data['search_base'], search_filter, attributes=attributes)
        
        if not conn.entries:
            log_to_file("LDAP sorgusu sonuç döndürmedi!", username=postuser)
            summary_output("getUserList: Hiçbir kullanıcı bulunamadı")
            conn.unbind()
            return jsonify({'message': 'No users found!', 'status': 'success', 'users': []}), 200
        
        users = []
        for entry in conn.entries:
            user_info = {
                'username': entry.sAMAccountName.value if entry.sAMAccountName else None,
                'display_name': entry.cn.value if entry.cn else None,
                'email': entry.mail.value if entry.mail else None,
                'job_title': entry.title.value if entry.title else None
            }
            users.append(user_info)
        
        log_to_file(f"Kullanıcı listesi alındı: {len(users)} kullanıcı bulundu.", username=postuser)
        summary_output(f"getUserList: {len(users)} kullanıcı listelendi")
        conn.unbind()
        
        if response_format.lower() == 'xml':
            xml_data = to_xml(users)
            return app.response_class(response=xml_data, mimetype='application/xml'), 200
        else:
            return jsonify({'message': 'Users retrieved successfully!', 'status': 'success', 'users': users}), 200
    
    except Exception as e:
        log_to_file(f"getUserList hatası: {str(e)}", username=postuser)
        summary_output("getUserList: Hata oluştu")
        if 'conn' in locals():
            conn.unbind()
        return jsonify({'message': f'Error: {str(e)}', 'status': 'error'}), 500

@app.route('/setUserPassword', methods=['POST'])
def set_user_password():
    data = request.get_json(silent=True)
    postuser = data.get('postuser') if data else None
    log_to_file("setUserPassword endpoint'ine istek geldi.", username=postuser)
    summary_output("setUserPassword: İstek alındı")
    
    try:
        if data is None:
            log_to_file("Gelen veri None! JSON formatı geçersiz.", username=postuser)
            return jsonify({'message': 'Invalid JSON data!', 'status': 'error'}), 400
        log_to_file(f"Gelen Veri: {json.dumps(data, indent=4)}", username=postuser)
        
        if not verify_token(data):
            return jsonify({'message': 'Invalid or missing token!', 'status': 'invalid_token'}), 403
        
        username = data.get('username')
        new_password = data.get('new_password')
        
        if not username or not new_password:
            log_to_file("Eksik parametre: username ve new_password gerekli!", username=postuser)
            summary_output("setUserPassword: Eksik parametre")
            return jsonify({'message': 'Username and new_password are required!', 'status': 'missing_parameters'}), 400
        
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(config_data['ad_server'], port=636, use_ssl=True, tls=tls_config, get_info=ALL)
        conn = Connection(server, config_data['ad_user'], decrypt_password(config_data['ad_password']), auto_bind=True)
        log_to_file("LDAPS bağlantısı başarılı!", username=postuser)
        summary_output("setUserPassword: Bağlantı başarılı")
        
        search_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
        conn.search(config_data['search_base'], search_filter, attributes=['distinguishedName'])
        
        if not conn.entries:
            log_to_file(f"Kullanıcı bulunamadı: {username}", username=postuser)
            summary_output("setUserPassword: Kullanıcı bulunamadı")
            conn.unbind()
            return jsonify({'message': f'User {username} not found!', 'status': 'not_found'}), 404
        
        user_dn = conn.entries[0].distinguishedName.value
        encoded_password = f'"{new_password}"'.encode('utf-16-le')
        conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [encoded_password])]})
        
        if conn.result['description'] != 'success':
            log_to_file(f"Şifre güncelleme hatası: {conn.result}", username=postuser)
            summary_output("setUserPassword: Şifre güncelleme başarısız")
            conn.unbind()
            return jsonify({'message': conn.result['description'], 'status': 'error'}), 400
        
        log_to_file(f"{username} kullanıcısının şifresi güncellendi!", username=postuser)
        summary_output(f"setUserPassword: {username} şifresi güncellendi")
        conn.unbind()
        return jsonify({'message': f'Password for {username} updated successfully!', 'status': 'success'}), 200
    
    except Exception as e:
        log_to_file(f"setUserPassword hatası: {str(e)}", username=postuser)
        summary_output("setUserPassword: Hata oluştu")
        if 'conn' in locals():
            conn.unbind()
        return jsonify({'message': f'Error: {str(e)}', 'status': 'error'}), 500

@app.route('/addUser', methods=['POST'])
def add_user():
    data = request.get_json(silent=True)
    postuser = data.get('postuser') if data else None
    log_to_file("addUser endpoint'ine istek geldi.", username=postuser)
    summary_output("addUser: İstek alındı")
    
    try:
        if data is None:
            log_to_file("Gelen veri None! JSON formatı geçersiz.", username=postuser)
            return jsonify({'message': 'Invalid JSON data!', 'status': 'error'}), 400
        log_to_file(f"Gelen Veri: {json.dumps(data, indent=4)}", username=postuser)
        
        if not verify_token(data):
            return jsonify({'message': 'Invalid or missing token!', 'status': 'invalid_token'}), 403
        
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        display_name = data.get('display_name')
        telephone_number = data.get('telephone_number')
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        domain_name = data.get('domain_name')
        job_title = data.get('job_title')
        department = data.get('department')
        company = data.get('company')
        member_of = data.get('member_of', [])
        create_ou_path = data.get('create_ou_path')
        
        required_fields = {'first_name': first_name, 'last_name': last_name, 'display_name': display_name,
                           'username': username, 'password': password, 'create_ou_path': create_ou_path}
        missing_fields = [field for field, value in required_fields.items() if not value]
        if missing_fields:
            log_to_file(f"Eksik parametreler: {', '.join(missing_fields)}", username=postuser)
            summary_output("addUser: Eksik parametre")
            return jsonify({'message': f"Missing required fields: {', '.join(missing_fields)}", 'status': 'missing_parameters'}), 400
        
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(config_data['ad_server'], port=636, use_ssl=True, tls=tls_config, get_info=ALL)
        conn = Connection(server, config_data['ad_user'], decrypt_password(config_data['ad_password']), auto_bind=True)
        log_to_file("LDAPS bağlantısı başarılı!", username=postuser)
        summary_output("addUser: Bağlantı başarılı")
        
        user_dn = f'CN={display_name},{create_ou_path}'
        user_principal_name = f"{username}@{domain_name}" if domain_name else f"{username}@server.local"
        encoded_password = f'"{password}"'.encode('utf-16-le')
        
        conn.add(user_dn, ['user'], {
            'givenName': first_name,
            'sn': last_name,
            'displayName': display_name,
            'telephoneNumber': telephone_number,
            'mail': email,
            'sAMAccountName': username,
            'unicodePwd': encoded_password,
            'userPrincipalName': user_principal_name,
            'title': job_title,
            'department': department,
            'company': company,
            'userAccountControl': 512
        })
        
        if conn.result['description'] != 'success':
            log_to_file(f"Kullanıcı ekleme hatası: {conn.result}", username=postuser)
            summary_output("addUser: Kullanıcı ekleme başarısız")
            conn.unbind()
            return jsonify({'message': conn.result['description'], 'status': 'error'}), 400
        
        log_to_file(f"Kullanıcı {username} başarıyla eklendi!", username=postuser)
        
        if member_of:
            for group in member_of:
                group_dn = f'{group}'
                conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
                if conn.result['description'] != 'success':
                    log_to_file(f"Gruba ekleme hatası ({group}): {conn.result}", username=postuser)
                    summary_output(f"addUser: {group} grubuna ekleme başarısız")
                    conn.unbind()
                    return jsonify({'message': f'Failed to add user to group {group}: {conn.result["description"]}', 'status': 'error'}), 400
                log_to_file(f"Kullanıcı {username} {group} grubuna eklendi!", username=postuser)
        
        summary_output(f"addUser: {username} oluşturuldu ve gruplara eklendi")
        conn.unbind()
        return jsonify({'message': f'User {username} created and added to groups successfully!', 'status': 'success'}), 201
    
    except Exception as e:
        log_to_file(f"addUser hatası: {str(e)}", username=postuser)
        summary_output("addUser: Hata oluştu")
        if 'conn' in locals():
            conn.unbind()
        return jsonify({'message': f'Error: {str(e)}', 'status': 'error'}), 500

@app.route('/functions', methods=['GET'])
def get_functions():
    log_to_file("functions endpoint'ine istek geldi.")
    summary_output("functions: İstek alındı")
    
    sample_token = "your_token1"
    endpoints = [
        {
            "name": "addContact",
            "method": "POST",
            "url": f"http://{SERVER_HOST}:{SERVER_PORT}/addContact",
            "description": "Yeni bir kontakt oluşturur ve belirtilen gruplara ekler.",
            "request_example": json.dumps({
                "postuser": "admin",
                "first_name": "John",
                "display_name": "John Doe",
                "description": "Test User",
                "email": "johndoe@example.com",
                "job_title": "Engineer",
                "department": "IT",
                "company": "Example Corp",
                "member_of": ["CN=TestGroup1,OU=Groups,DC=SERVER,DC=LOCAL", "CN=TestGroup2,OU=Groups,DC=SERVER,DC=LOCAL"],  # member_of listesi
                "create_ou_path": "OU=Contacts,DC=SERVER,DC=LOCAL",
                "token": sample_token
            }, indent=2),
            "response_example": json.dumps({"message": "Contact John Doe created and added to groups successfully!", "status": "success"}, indent=2)
        },
        {
            "name": "getUserList",
            "method": "POST",
            "url": f"http://{SERVER_HOST}:{SERVER_PORT}/getUserList",
            "description": "Kullanıcıları listeler (JSON veya XML).",
            "request_example_json": json.dumps({"postuser": "admin", "token": sample_token, "format": "json"}, indent=2),
            "request_example_xml": json.dumps({"postuser": "admin", "token": sample_token, "format": "xml"}, indent=2),
            "response_example": json.dumps({"message": "Users retrieved successfully!", "status": "success", "users": [{"username": "jdoe", "display_name": "John Doe", "email": "jdoe@example.com", "job_title": "Engineer"}]}, indent=2),
            "response_example_xml": to_xml([{"username": "jdoe", "display_name": "John Doe", "email": "jdoe@example.com", "job_title": "Engineer"}])
        },
        {
            "name": "setUserPassword",
            "method": "POST",
            "url": f"http://{SERVER_HOST}:{SERVER_PORT}/setUserPassword",
            "description": "Kullanıcı şifresini günceller.",
            "request_example": json.dumps({"postuser": "admin", "username": "jdoe", "new_password": "NewPass123!", "token": sample_token}, indent=2),
            "response_example": json.dumps({"message": "Password for jdoe updated successfully!", "status": "success"}, indent=2)
        },
        {
            "name": "addUser",
            "method": "POST",
            "url": f"http://{SERVER_HOST}:{SERVER_PORT}/addUser",
            "description": "Yeni bir kullanıcı oluşturur ve belirtilen gruplara ekler.",
            "request_example": json.dumps({
                "postuser": "admin",
                "first_name": "Jane",
                "last_name": "Smith",
                "display_name": "Jane Smith",
                "telephone_number": "+1234567890",
                "email": "jane.smith@example.com",
                "username": "jsmith",
                "password": "Pass123!",
                "domain_name": "server.local",
                "job_title": "Manager",
                "department": "HR",
                "company": "Example Corp",
                "member_of": ["CN=Group1,OU=Groups,DC=SERVER,DC=LOCAL", "CN=Group2,OU=Groups,DC=SERVER,DC=LOCAL"],
                "create_ou_path": "OU=Users,DC=SERVER,DC=LOCAL",
                "token": sample_token
            }, indent=2),
            "response_example": json.dumps({"message": "User jsmith created and added to groups successfully!", "status": "success"}, indent=2)
        }
    ]
    
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>AD Rest Service - Functions</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #333; }
            .endpoint { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; }
            pre { background: #f4f4f4; padding: 10px; }
        </style>
    </head>
    <body>
        <h1>AD Rest Service - API Functions</h1>
        {% for endpoint in endpoints %}
            <div class="endpoint">
                <h2>{{ endpoint.name }} ({{ endpoint.method }})</h2>
                <p><strong>URL:</strong> <a href="{{ endpoint.url }}">{{ endpoint.url }}</a></p>
                <p><strong>Description:</strong> {{ endpoint.description }}</p>
                <p><strong>Request Example:</strong></p>
                {% if endpoint.name == "getUserList" %}
                    <p>For JSON:</p><pre>{{ endpoint.request_example_json }}</pre>
                    <p>For XML:</p><pre>{{ endpoint.request_example_xml }}</pre>
                {% else %}
                    <pre>{{ endpoint.request_example }}</pre>
                {% endif %}
                <p><strong>Response Example:</strong></p>
                <pre>{{ endpoint.response_example }}</pre>
                {% if endpoint.name == "getUserList" %}
                    <p><strong>Response Example (XML):</strong></p><pre>{{ endpoint.response_example_xml }}</pre>
                {% endif %}
            </div>
        {% endfor %}
    </body>
    </html>
    """
    log_to_file("functions sayfası oluşturuldu.")
    summary_output("functions: Sayfa döndürüldü")
    return render_template_string(html_template, endpoints=endpoints)

# Flask'ı çalıştırma
def run_flask():
    log_to_file("Flask sunucusu başlatılıyor.")
    summary_output("Flask sunucusu başlatılıyor")
    app.run(host=SERVER_HOST, port=SERVER_PORT)

# GUI ve başlangıç
app_gui = tk.Tk()
app_gui.title("Rest Servis Durumu")
output_text = scrolledtext.ScrolledText(app_gui, width=80, height=20)
output_text.pack()

# Başlangıç mesajları
log_initial_info = (
    f"Rest Servis Başlatılıyor...\n"
    f"Host: {SERVER_HOST}\n"
    f"Port: {SERVER_PORT}\n"
    f"Servis URL'leri:\n"
    f"- POST http://{SERVER_HOST}:{SERVER_PORT}/addContact\n"
    f"- POST http://{SERVER_HOST}:{SERVER_PORT}/getUserList\n"
    f"- POST http://{SERVER_HOST}:{SERVER_PORT}/setUserPassword\n"
    f"- POST http://{SERVER_HOST}:{SERVER_PORT}/addUser\n"
    f"- GET http://{SERVER_HOST}:{SERVER_PORT}/functions\n"
)
summary_output(log_initial_info)
log_to_file("Program başlatıldı.")
print("Rest Servis Başlatıldı.")  # Konsola yalnızca başlangıç mesajı

# Şifre kontrolü
check_and_update_password()

# Flask'ı ayrı thread'de başlat
threading.Thread(target=run_flask, daemon=True).start()

# GUI döngüsü
app_gui.mainloop()