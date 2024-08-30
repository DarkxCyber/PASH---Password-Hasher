# PASH: Password Hashing Tool

PASH is a Python-based GUI application designed to hash passwords securely using various algorithms. This tool supports multiple hashing algorithms like bcrypt, SHA-256, SHA-1, MD5, SHA-512, SHA-384, and SHA-224, making it versatile for different security needs. PASH also features a password strength checker, customization options, and the ability to save hashed passwords to a file.

*Features*

  1. Multi-Algorithm Support: 
              Hash passwords using algorithms such as bcrypt, SHA-256, SHA-1, MD5, SHA-512, SHA-384, and SHA-224.
  2. Password Strength Checker: 
              Provides real-time feedback on password strength with a visual strength bar.
  3. Password Visibility Toggle: 
              Easily show or hide the entered password.
  4. Save Hashed Passwords: 
              Save the generated hashed passwords to a file for future use.
  5. Truncate Hashed Passwords: 
              Option to truncate the hashed password to a specified length.

*Installation*

Clone the repository:
    git clone https://github.com/yourusername/PASH.git

Install dependencies:
  PASH requires the following Python libraries:
    pip install bcrypt

*Usage*

Run the application:
    python pash.py

Step 1: 
  Enter a password: Input the password you want to hash in the provided field.

Step 2:
  Select an algorithm: Choose the desired hashing algorithm from the dropdown menu.

Step 3:
  Check password strength: As you type, the password strength will be displayed along with a strength bar.

Step 4:
  Hash the password: Click the "Hash Password" button to generate the hashed password.

Step 5:
  Save the hashed password: If needed, click "Save Hashed Password" to store the result in a text file.
