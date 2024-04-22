# AutoSSL

## Introduction
AutoSSL is a system that facilitates the management of SSL certificates for domains, allowing users to view the status of their domains and associated SSL certificates. Additionally, it provides functionality to renew these certificates through a web interface.

## Features
- **Status View**: View the current status of SSL certificates through a web interface.
- **Certificate Renewal**: Allows for the renewal of certificates using a `.zip` file that contains the private key and the certificate.
- **Rollback**: Functionality to revert to a previous certificate if necessary.

## Prerequisites
- **Server Operating System**: Linux.
- **Supported Web Servers**: Apache2 (minimum version 2.2.0) and NGINX (minimum version 1.0.0).

## Installation
1. Clone or download the files from this repository.
2. Register on the [AutoSSL web page](URL_OF_THE_WEB_PAGE) and generate an agent. This will provide you with an `agent-details.json` file.
3. Place the `agent-details.json` file in the same directory as the other files downloaded from this repository.

## Usage
- Run the AutoSSL agent on your server. It will remain active continuously to monitor and manage certificates.
- Interact with the system through the web application to view certificate status, renew them, or perform a rollback to a previous certificate version.

## Contribution
Contributions are welcome. If you are interested in improving AutoSSL, please contact me via email to contact me via email to comment on possible improvements and/or bug fixes.

---

### Contact
For more information or support, contact Alejandro Valdivia Muñoz via:
- Email: [alexxvaldii01@gmail.com](mailto:alexxvaldii01@gmail.com)
- LinkedIn: [Alejandro Valdivia Muñoz](https://www.linkedin.com/in/alejandro-valdivia-mu%C3%B1oz-724598290/)
- GitHub: [AlexValdi01](https://github.com/AlexValdi01)
