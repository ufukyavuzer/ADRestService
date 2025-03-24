# AD Rest Service

A Python-based RESTful API service for managing Active Directory (AD) objects such as users and contacts using the `ldap3` library. This service allows you to create users and contacts, update user passwords, and retrieve user lists via HTTP endpoints, with LDAP integration for secure AD operations.

Built with Flask, it provides a simple GUI for monitoring and supports encrypted credentials for enhanced security.

---

## Features
- **Create Contacts**: Add new contacts to specified Organizational Units (OUs) and assign them to multiple AD groups.
- **Create Users**: Add new users with customizable attributes and assign them to multiple AD groups.
- **Update Passwords**: Change user passwords securely via LDAP.
- **Retrieve User List**: Fetch a list of users in JSON or XML format, filtered by include/exclude group membership.
- **Dynamic OU Support**: Specify OU paths dynamically via API requests.
- **Security**: Token-based authentication and encrypted AD credentials.
- **Logging**: Detailed logs for all operations.
- **GUI**: A basic Tkinter-based interface for real-time service monitoring.

---

## Prerequisites
Before you begin, ensure you have the following installed:
- Python 3.8 or higher
- pip (Python package manager)
- An Active Directory environment with LDAPS (LDAP over SSL) enabled
- Administrative credentials for AD operations
  ```bash
  pip install flask ldap3 tkinter cryptography pyinstaller
  
---

## Installation
Follow these steps to set up the project locally:
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/ufukyavuzer/ADRestService.git
   cd ADRestService
   
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt

   Required packages:
   - `flask`
   - `ldap3`
   - `cryptography`
   - `tk`
   - `pyinstaller`
  
3. **Configure the Service**:
   - The first run will generate a `config.txt` file.
   - Update the file with your AD details:
     ```json
     {
       "ad_server": "ldaps://server.local",
       "ad_user": "administrator@yourdomain.local",
       "ad_password": "your_ad_password",
       "search_base": "DC=YOURDOMAIN,DC=LOCAL",
       "tokens": ["your_token1", "your_token2"],
       "include_list": ["OU=IncludeOU,DC=YOURDOMAIN,DC=LOCAL"],
       "exclude_list": ["CN=Administrators,CN=Builtin,DC=YOURDOMAIN,DC=LOCAL"]
     }
   - On the next run, the password will be encrypted and stored securely.

4. **Run the Service**:
   ```bash
   python adRestService.py
   - The Flask server will start on `0.0.0.0:5000`.
   - A Tkinter GUI will display service status and logs.

5. **Configuration**
The `config.txt` file contains the following default settings:
    ```json
    {
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


- **ad_server**: Your AD server's LDAPS URL.
- **ad_user**: AD admin username.
- **ad_password**: AD admin password (encrypted on first run).
- **search_base**: Base DN for LDAP searches.
- **tokens**: List of API authentication tokens.
- **include_list**: OUs or groups to include in user searches.
- **exclude_list**: OUs or groups to exclude from user searches.

## Building the Executable
### Using Provided Scripts 
1. **Windows**:
  Run the provided `build.bat` script in the project directory:
    ```bat
    build.bat
  
  This will generate the executable in `Output\dist\adRestService.exe`.
  
2. **Linux/Mac**:
  Run the provided `build.sh` script (make it executable first with `chmod +x build.sh`):
    ```bash
    ./build.sh
  
  This will generate the executable in `Output/dist/adRestService`.

### Notes
- Ensure `favicon.ico` is in the project directory.
- UPX is included in the project under the `upx` directory. The build scripts use it by default for compression. If you want to disable compression, remove the `--upx-dir upx` parameter from the scripts.


## Usage
The service exposes the following endpoints. Use tools like `curl` or Postman to interact with the API.

1. **Access the API**:
   Use tools like `curl` or Postman to interact with the endpoints. Example:
   ```bash
   curl -X POST http://localhost:5000/addUser \
   -H "Content-Type: application/json" \
   -d '{"postuser": "admin", "first_name": "Jane", "last_name": "Smith", "display_name": "Jane Smith", "username": "jsmith", "password": "Pass123!", "create_ou_path": "OU=Users,DC=SERVER,DC=LOCAL", "token": "your_token1"}'

## Features
- **Endpoints**:
  - `POST /addContact`: Create a new AD contact and optionally add it to groups.
  - `POST /getUserList`: Retrieve a list of AD users in JSON or XML format.
  - `POST /setUserPassword`: Update an AD user's password.
  - `POST /addUser`: Create a new AD user and optionally add it to groups.
  - `GET /functions`: View API documentation with request/response examples.
 
- **Security**:
  - Token-based authentication.
  - Encrypted AD password storage using Fernet (symmetric encryption).
  - LDAPS (LDAP over SSL) for secure communication with Active Directory.

- **GUI**: A Tkinter-based interface to monitor service activity in real-time.
- **Logging**: Detailed logs saved to `service.log`.

## API Documentation
Visit `http://localhost:5000/functions` to see detailed endpoint documentation, including request and response examples.

## Contributing
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- Built with [Flask](https://flask.palletsprojects.com/), [ldap3](https://ldap3.readthedocs.io/), [cryptography](https://cryptography.io/), and [PyInstaller](https://pyinstaller.org/).
- Thanks to the open-source community!
