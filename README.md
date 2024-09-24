# SecureVault - Java Project

## Overview
**SecureVault** is a Java-based application that provides secure image encryption and decryption services to ensure the confidentiality and integrity of sensitive image data. This application utilizes the **Advanced Encryption Standard (AES)** for encrypting and decrypting images. It also employs user authentication and a MySQL database for securely storing user details and file metadata.

## Features
- **AES Encryption & Decryption**: Encrypts and decrypts images using a user-defined key with AES encryption.
- **User Authentication**: Secure login and registration system to ensure only authorized users can encrypt and decrypt images.
- **MySQL Database**: Stores user information and encrypted file metadata securely.
- **Change Password**: Users can update their account passwords.
- **Error Handling**: Graceful handling of errors, ensuring reliability in database operations and file handling.
- **Graphical User Interface (GUI)**: User-friendly interface built using Java Swing for seamless interaction.

## Technologies Used
- **Java**: The core programming language for the application.
- **Swing**: Used for creating the graphical user interface.
- **MySQL**: Database for storing user details and encrypted file metadata.
- **JDBC**: For database connectivity between the Java application and MySQL.
- **AES Encryption**: Encrypts and decrypts images using a user-defined key.
- **SHA-256 Hashing**: Used for verifying file integrity and key validation.

## Modules Description

### 1. User Authentication
This module ensures that users can securely register and log in to the application. It verifies credentials against stored data in the MySQL database.
- **Functions**: `authur()`, `uexs()`, `cusr()`
- **Description**: These methods validate user credentials, check user existence, and manage user registration.

### 2. AES Encryption
The core module encrypts user-selected images using the AES algorithm with a user-provided encryption key.
- **Function**: `encrf(File fileToEncrypt, String userDefinedKey)`
- **Description**: Encrypts an image file using AES encryption. The user provides a key that is hashed and padded to create a secure encryption key.

### 3. AES Decryption
This module allows users to decrypt previously encrypted images by entering the correct encryption key.
- **Function**: `decrf(File fileToDecrypt, String userDefinedKey)`
- **Description**: Decrypts an encrypted image using the original key provided by the user.

### 4. Password Management
Allows users to change their account password securely.
- **Functions**: `chpwdb(String newPassword)`, `vpswd(String oldPassword)`
- **Description**: These methods verify the old password, and if correct, update it with the new password provided by the user.

### 5. File Metadata Management
This module handles the storage and retrieval of encrypted file metadata in the MySQL database.
- **Function**: `sfinfo()`
- **Description**: Stores metadata like file names and encryption keys in the database, ensuring the tracking of user-encrypted files.

### 6. Database Connection
Handles connections between the Java application and the MySQL database.
- **Function**: `connectToDB()`
- **Description**: Establishes a connection to the MySQL database using JDBC.

### 7. Error Handling
Ensures that errors encountered during database operations or file handling are gracefully managed.
- **Methodology**: Implements `try-catch` blocks and uses `JOptionPane` to alert users about errors.

### 8. Graphical User Interface (GUI)
The GUI allows users to interact with the application, including login, registration, file selection for encryption/decryption, and changing passwords.
- **Framework**: Java Swing
- **Components**: `JFrame`, `JPanel`, `JTextField`, `JButton`, `JPasswordField`

## How to Use

1. **Registration**: New users can register by entering a username and password. The application will store this information securely in the MySQL database.
2. **Login**: Registered users can log in by entering their username and password. Upon successful authentication, they will be granted access to encrypt and decrypt images.
3. **Encrypt Image**: Users can select an image file, enter a key, and encrypt the image. The encrypted file is saved, and metadata is stored in the database.
4. **Decrypt Image**: Users can select an encrypted file, enter the original key, and decrypt the image for viewing.
5. **Change Password**: Users can change their password by entering their old password and confirming the new one.

## Database Schema
- **Database Name**: `flencrdb`
- **Tables**:
  - `usr`: Stores user credentials (username, password).
  - `encryfls`: Stores metadata of encrypted files, such as filenames and associated encryption keys.

## Prerequisites
- **Java Development Kit (JDK)**: Version 8 or higher.
- **Integrated Development Environment (IDE)**: Eclipse, NetBeans, or IntelliJ IDEA.
- **MySQL Database**: Must be installed and configured with JDBC for database operations.
- **Libraries**: 
  - Java Swing for GUI.
  - `javax.crypto` package for encryption.
  
## Setup Instructions
1. Install JDK 8 or above.
2. Set up MySQL and create the required database and tables.
3. Clone the repository and open it in your preferred IDE.
4. Configure the MySQL database connection in the `myproj` class.
5. Run the project from the main class.


This project was developed as part of a mini-project focusing on secure file encryption using AES in Java.
