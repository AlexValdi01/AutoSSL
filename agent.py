# agent.py

import os
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import json
import requests
import socket
import subprocess
import pika
import base64
import zipfile
import time
import shutil
import threading
from constant_agent import APACHE_DIRECTORY, NGINX_DIRECTORY, MIN_VERSION_APACHE, MIN_VERSION_NGINX

def load_config():
    with open('config_agent.json', 'r') as config_file:
        return json.load(config_file)

config = load_config()

def load_detail():
    with open('agent-details.json', 'r') as file:
        return json.load(file)

detail = load_detail()

token = detail.get("token")

def get_apache_version():
    try:
        # Run the 'apache2 -v' command to get Apache version
        result = subprocess.run(['apache2', '-v'], capture_output=True, text=True)
        version_info = result.stdout.strip().split('\n')[0] if result.stdout else None
        version = version_info.split('/')[1].split()[0] if version_info else None
        return version
    except Exception as e:
        print(f"Error retrieving Apache version: {e}")
    return None

def get_nginx_version():
    try:
        # Run the 'nginx -v' command to get Nginx version
        result = subprocess.run(['nginx', '-v'], capture_output=True, text=True)
        version_info = result.stderr.strip().split('\n')[0] if result.stderr else None
        version = version_info.split('/')[1].split()[0] if version_info else None
        return version
    except Exception as e:
        print(f"Error retrieving Nginx version: {e}")
    return None

def compare_versions(version1, version2):
    # Split versions into parts
    parts1 = list(map(int, version1.split('.')))
    parts2 = list(map(int, version2.split('.')))

    # Pad with zeros to ensure they have the same length
    while len(parts1) < len(parts2):
        parts1.append(0)
    while len(parts2) < len(parts1):
        parts2.append(0)

    # Compare each part
    for part1, part2 in zip(parts1, parts2):
        if part1 < part2:
            return -1
        elif part1 > part2:
            return 1

    # If it reaches here, versions are equal
    return 0

def is_version_compatible(apache_version, min_version_apache, nginx_version, min_version_nginx):

    if (
        compare_versions(apache_version, min_version_apache) == -1
        or compare_versions(nginx_version, min_version_nginx) == -1
    ):
        return False
    return True

def is_domain_active(domain, ports):
    for port in ports:
        try:
            with socket.create_connection((domain, port), timeout=2) as connection:
                return "active"
        except (socket.timeout, socket.error, ConnectionRefusedError):
            pass
    return "inactive"

def get_certificate_info(cert_path):
    try:
        # Load the certificate
        with open(cert_path, 'rb') as cert_file:
            pem_data = cert_file.read()
            cert = x509.load_pem_x509_certificate(pem_data, default_backend())

        # Get certificate information
        subject = dict((name.oid._name, name.value) for name in cert.subject)
        issuer = dict((name.oid._name, name.value) for name in cert.issuer)
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after

        # Convert dates to strings
        not_before_str = not_before.strftime('%Y-%m-%d %H:%M:%S')
        not_after_str = not_after.strftime('%Y-%m-%d %H:%M:%S')

        # Return a dictionary with strings instead of Name objects
        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before_str,
            "not_after": not_after_str,
            "active": "Yes" if not_before < datetime.now() < not_after else "No"
        }
    except Exception as e:
        print(f"Error obtaining certificate information from {cert_path}: {e}")
        return None

def find_apache_domains_and_ports(directory):
    domain_pattern = re.compile(r'\bServerName\b\s+(\S+)')
    listen_pattern = re.compile(r'<VirtualHost\s+\*:(\d+)>')
    cert_path_pattern = re.compile(r'SSLCertificateFile\s+([^\s;]+)')
    result = {}
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            with open(file_path, 'r') as file:
                content = file.read()
                domains = domain_pattern.findall(content)
                ports = set(int(port) for port in listen_pattern.findall(content))
                cert_paths = cert_path_pattern.findall(content)
                for domain in domains:
                    status = is_domain_active(domain, ports)
                    result.setdefault(domain, {"files": set(), "ports": set(), 
                                               "web_server": "Apache", "status": status, 
                                               "cert_paths": set()}).get("files").add(filename)
                    result[domain]["ports"].update(ports)
                    result[domain]["cert_paths"].update(cert_paths)
    return result

def find_nginx_domains_and_ports(directory):
    domain_pattern = re.compile(r'\bserver_name\b\s+([^;]+);')
    listen_pattern = re.compile(r'\blisten\b\s+(\d+)')
    cert_path_pattern = re.compile(r'ssl_certificate\s+([^\s;]+)')
    result = {}
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            with open(file_path, 'r') as file:
                content = file.read()
                domains = domain_pattern.findall(content)
                ports = set(int(port) for port in listen_pattern.findall(content))
                cert_paths = cert_path_pattern.findall(content)
                for domain in domains:
                    status = is_domain_active(domain, ports)
                    result.setdefault(domain, {"files": set(), "ports": set(), 
                                               "web_server": "Nginx", "status": status, 
                                               "cert_paths": set()}).get("files").add(filename)
                    result[domain]["ports"].update(ports)
                    result[domain]["cert_paths"].update(cert_paths)
    return result

def find_apache_cert_paths(domain):
    cert_path_pattern = re.compile(r'SSLCertificateFile\s+([^\s;]+)')
    cert_paths = set()
    for filename in os.listdir(APACHE_DIRECTORY):
        file_path = os.path.join(APACHE_DIRECTORY, filename)
        if os.path.isfile(file_path):
            with open(file_path, 'r') as file:
                content = file.read()
                if domain in content:
                    cert_paths.update(cert_path_pattern.findall(content))
    return list(cert_paths)

def find_nginx_cert_paths(domain):
    cert_path_pattern = re.compile(r'ssl_certificate\s+([^\s;]+)')
    cert_paths = set()
    for filename in os.listdir(NGINX_DIRECTORY):
        file_path = os.path.join(NGINX_DIRECTORY, filename)
        if os.path.isfile(file_path):
            with open(file_path, 'r') as file:
                content = file.read()
                if domain in content:
                    cert_paths.update(cert_path_pattern.findall(content))
    return list(cert_paths)

def detect_web_server(domain):
    # Check the configuration files, skipping domain extensions
    apache_files = [f for f in os.listdir(APACHE_DIRECTORY) if f.startswith(domain.split('.')[0])]
    nginx_files = [f for f in os.listdir(NGINX_DIRECTORY) if f.startswith(domain.split('.')[0])]
    if apache_files:
        return "apache"
    elif nginx_files:
        return "nginx"
    return None

def is_service_active(service_name):
    # Check if the service is active
    result = subprocess.run(["systemctl", "is-active", service_name], text=True, capture_output=True)
    return result.stdout.strip() == 'active'

send_data_event = threading.Event()

def send_data_to_backend():
    apache_version = get_apache_version()
    nginx_version = get_nginx_version()
    min_version_apache = MIN_VERSION_APACHE
    min_version_nginx = MIN_VERSION_NGINX

    headers = {"Authorization": f"Bearer {token}"}

    if not is_version_compatible(apache_version, min_version_apache, nginx_version, min_version_nginx):
        message = None
        if compare_versions(apache_version, min_version_apache) == -1:
            message = "Incompatible version of Apache. Please update Apache."
        elif compare_versions(nginx_version, min_version_nginx) == -1:
            message = "Incompatible version of Nginx. Please update Nginx."

        if message:
            combined_info = {
                "message": message,
                "apache_version": apache_version,
                "nginx_version": nginx_version,
                "min_version_apache": min_version_apache,
                "min_version_nginx": min_version_nginx,
            }

            backend_url = config.get("backend_url")
            response = requests.post(backend_url, json=combined_info, headers=headers)

            if response.status_code == 200:
                print(f"[!] Message sent to the backend.")
            else:
                print(f"[!] Error sending information to the backend: {response.status_code}")

    else:
        apache_directory = APACHE_DIRECTORY
        nginx_directory = NGINX_DIRECTORY

        apache_data = find_apache_domains_and_ports(apache_directory)
        nginx_data = find_nginx_domains_and_ports(nginx_directory)

        all_data = {**apache_data, **nginx_data}

        for domain, info in all_data.items():
            web_server = info["web_server"]
            files = ', '.join(info["files"])
            ports = ', '.join(map(str, info["ports"]))
            status = info["status"]

            print(f"\n[+] Information about web server configuration:")
            print(f"Web server: {web_server}")
            print(f"Domain: {domain}")
            print(f"Status: {status}")
            print(f"Files: {files}")
            print(f"Ports: {ports}")
            print()

            cert_info = None

            for cert_path in info["cert_paths"]:
                cert_info_temp = get_certificate_info(cert_path)

                if cert_info_temp is not None:
                    print("[+] Certificate Information:")
                    print(f"Subject: {cert_info_temp['subject']}")
                    print(f"Issuer: {cert_info_temp['issuer']}")
                    print(f"Not before: {cert_info_temp['not_before']}")
                    print(f"Not after: {cert_info_temp['not_after']}")
                    print(f"Active: {cert_info_temp['active']}")
                    cert_info = cert_info_temp

            combined_info = {
                "web_server": web_server,
                "domain": domain,
                "status": status,
                "files": list(info["files"]),
                "ports": list(info["ports"]),
                "subject": cert_info['subject'] if cert_info else None,
                "issuer": cert_info['issuer'] if cert_info else None,
                "not_before": cert_info['not_before'] if cert_info else None,
                "not_after": cert_info['not_after'] if cert_info else None,
                "active": cert_info['active'] if cert_info else None,
            }

            backend_url = config.get("backend_url")
            response = requests.post(backend_url, json=combined_info, headers=headers)

            if response.status_code == 200:
                print("[✓] Certificate information was successfully sent to the backend.")
            elif response.status_code == 403:
                print("\n[!] Error: Invalid or expired agent token")
            else:
                print(f"\n[!] Error sending information to the backend: {response.status_code}")
    
def send_data_periodically():
    while True:
        send_data_to_backend()
        send_data_event.wait(timeout=120)
        send_data_event.clear()        

def manage_web_servers(target_service):
    other_service = "apache2" if target_service == "nginx" else "nginx"
    target_active = is_service_active(target_service)
    other_active = is_service_active(other_service)

    try:
        if target_active:
            subprocess.run(["systemctl", "restart", target_service], check=True)
            print(f"{target_service} restarted successfully.")
        else:
            if other_active:
                subprocess.run(["systemctl", "stop", other_service], check=True)
                print(f"{other_service} stopped successfully.")
            subprocess.run(["systemctl", "start", target_service], check=True)
            print(f"{target_service} started successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error managing web servers: {e}")

def connect_to_rabbitmq():
    credentials = pika.PlainCredentials(detail["rabbitmq_username"], 
                                        detail["rabbitmq_password"])
    parameters = pika.ConnectionParameters(host=config["rabbitmq_host"], 
                                           port=int(config["rabbitmq_port"]), 
                                           virtual_host=config["rabbitmq_vhost"], 
                                           credentials=credentials)
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    return connection, channel

def check_and_process_messages():
    connection, channel = connect_to_rabbitmq()

    def callback(ch, method, properties, body):
        print("Processing message intended for this agent.")
        process_message(json.loads(body.decode('utf-8')))
        ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=detail["queue_name"], on_message_callback=callback, auto_ack=False)
    try:
        channel.start_consuming()  # Start consuming indefinitely
    except KeyboardInterrupt:
        channel.stop_consuming()
    connection.close()

def send_heartbeat():
    heartbeat_url = f"{config['backend_url']}/agents/heartbeat"
    headers = {"Authorization": f"Bearer {token}"}
    data = {
        'agent_id': detail["agent_id"],
        'timestamp': datetime.utcnow().isoformat()
    }
    response = requests.post(heartbeat_url, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        print("Heartbeat sent successfully.")
    else:
        print("Failed to send heartbeat.", response.text)

def start_heartbeat_interval(interval=60):
    while True:
        send_heartbeat()
        time.sleep(interval)

def process_message(message):
    domain = message.get("domain")
    action = message.get("action", "renew")

    if action == "rollback":
        handle_rollback(domain)
    else:
        handle_renewal(message)
    send_data_event.set()

def handle_renewal(message):
    domain = message.get("domain")
    file_content_base64 = message.get("file_content")
    file_content = base64.b64decode(file_content_base64)
    temp_zip_path = f"/tmp/{domain}.zip"

    # Save the .zip file temporarily
    with open(temp_zip_path, "wb") as temp_zip_file:
        temp_zip_file.write(file_content)

    # Unzip the file
    with zipfile.ZipFile(temp_zip_path, 'r') as zip_ref:
        zip_ref.extractall(f"/tmp/{domain}")

    # Get the web server configured for the domain
    web_server = detect_web_server(domain.split('.')[0])
    if not web_server:
        print("No web server configuration found for the domain.")
        return

    # Get the certificate paths from the configuration file
    cert_paths = []
    if web_server == "apache":
        cert_paths = find_apache_cert_paths(domain)
    elif web_server == "nginx":
        cert_paths = find_nginx_cert_paths(domain)

    if not cert_paths:
        print(f"No certificate paths found in the configuration for {domain}.")
        return

    # Update the certificates in their original locations
    for cert_path in cert_paths:
        cert_directory = os.path.dirname(cert_path)
        backup_directory = os.path.join(cert_directory, "backup", datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))

        # Create the backup directory
        os.makedirs(backup_directory, exist_ok=True)

        # Move current files to the backup directory
        for filename in os.listdir(cert_directory):
            if filename.endswith(".key") or filename.endswith(".crt"):
                shutil.move(os.path.join(cert_directory, filename), os.path.join(backup_directory, filename))

        # Copy new files from /tmp/{domain} to the original directory
        for filename in os.listdir(f"/tmp/{domain}"):
            if filename.endswith(".key") or filename.endswith(".crt"):
                shutil.copy(os.path.join(f"/tmp/{domain}", filename), cert_directory)

    # Clean up the temporary .zip file and the temporary directory
    os.remove(temp_zip_path)
    shutil.rmtree(f"/tmp/{domain}")

    if web_server:
        manage_web_servers(web_server)
        print(f"Certificate renewed and {web_server.capitalize()} successfully restarted for domain {domain}.")

def handle_rollback(domain):
    try:
        # Get the web server configured for the domain
        web_server = detect_web_server(domain.split('.')[0])
        if not web_server:
            print("No web server configuration found for the domain.")
            return

        # Get the certificate paths from the configuration file
        cert_paths = []
        if web_server == "apache":
            cert_paths = find_apache_cert_paths(domain)
        elif web_server == "nginx":
            cert_paths = find_nginx_cert_paths(domain)

        if not cert_paths:
            print(f"No certificate paths found in the configuration for {domain}.")
            return

        for cert_path in cert_paths:
            cert_directory = os.path.dirname(cert_path)
            backup_directory = os.path.join(cert_directory, "backup")

            # Ensure there are backups available
            backup_folders = [d for d in os.listdir(backup_directory) if os.path.isdir(os.path.join(backup_directory, d))]
            if not backup_folders:
                print(f"No backups found for domain {domain}. Rollback aborted.")
                return

            # Find the latest backup folder
            latest_backup = max([os.path.join(backup_directory, d) for d in backup_folders], key=os.path.getmtime)

            # Remove current certificate files safely
            current_files = [f for f in os.listdir(cert_directory) if os.path.isfile(os.path.join(cert_directory, f))]
            for filename in current_files:
                os.remove(os.path.join(cert_directory, filename))

            # Copy files from the latest backup to the certificate directory
            backup_files = [f for f in os.listdir(latest_backup) if os.path.isfile(os.path.join(latest_backup, f))]
            for filename in backup_files:
                shutil.copy(os.path.join(latest_backup, filename), cert_directory)

        if web_server:
            manage_web_servers(web_server)
            print(f"Rollback successful and {web_server.capitalize()} restarted for domain {domain}.")
        else:
            print("No web server configuration found for the domain.")
    except Exception as e:
        print(f"Error during rollback for domain {domain}: {e}")

def main():
    # Thread to process RabbitMQ messages
    thread_rabbitmq = threading.Thread(target=check_and_process_messages)

    # Thread to send server data every 30 minutes
    thred_send_data = threading.Thread(target=send_data_periodically)

    # Thread to indicate that the agent is active to the backend
    thread_heartbeat = threading.Thread(target=start_heartbeat_interval)

    thread_rabbitmq.start()
    thred_send_data.start()
    thread_heartbeat.start()
    
    thread_rabbitmq.join()
    thred_send_data.join()

if __name__ == "__main__":
    main()
