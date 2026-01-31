## Secure File Vault (AES & RSA Based)

About the Project
Secure File Vault is a secure file storage system developed to protect sensitive files using **hybrid encryption techniques**.  
The project combines **AES (Advanced Encryption Standard)** for encrypting file data and **RSA (Rivest–Shamir–Adleman)** for securely sharing encryption keys.

This project was created to understand how cryptography and access control are used in real-world secure systems.

## Project Objectives
- To securely store files using encryption
- To control access using user roles
- To ensure file integrity using hashing
- To understand practical implementation of AES and RSA


## Key Features
- Hybrid encryption using **AES + RSA**
- Secure key generation and management
- File integrity verification using hashing
- Role-based access control (Admin & User)
- Upload, read, share, and delete files
- Simple and easy-to-use interface
- Cloud-ready architecture

## How the Security Works
1. Files are encrypted using **AES** before storage.
2. The AES key is encrypted using an **RSA public key**.
3. Only authorized users can decrypt the AES key using their **RSA private key**.
4. A hash is stored to verify file integrity.
5. Admin manages users and access permissions.

##  User Roles
### Admin
- Add and manage users
- Assign roles and permissions
- Manage encryption keys
- Control file access

### User
- Upload encrypted files
- Access authorized files
- Share files securely
- Verify file integrity

## Technologies Used
- Python
- AES & RSA Cryptography
- Hashing Algorithms
- Git & GitHub
- Cloud-based storage design

##  Project Structure
Secure-File-Vault/
│
├── backend/
├── src/
├── app.py
├── crypto.py
├── cloud.py
├── roles.py
├── secure_vault_gui.py
├── add_new_user.py
├── delete_file.py
├── list_files.py
├── share_file.py
├── generate_keys.py
├── config.py
├── .gitignore
└── README.md

---

## How to Run the Project
1. Clone the repository:
git clone https://github.com/Kushal-Gowda-L/Secure-File-Vault.git

2. Navigate to the project folder:
cd Secure-File-Vault

3. Create and activate a virtual environment:
python -m venv .venv
.venv\Scripts\activate

4. Install required dependencies:
pip install -r requirements.txt

5. Run the application

---

##  Academic Significance
This project demonstrates:
- Secure file handling techniques
- Practical use of cryptography
- Role-based access control systems
- Secure cloud-based storage concepts

---

##  Future Enhancements
- Web-based interface
- Database integration
- Multi-user authentication
- Activity logging
- Two-factor authentication

---

## Author
**Kushal Gowda L**  
GitHub: https://github.com/Kushal-Gowda-L

---
