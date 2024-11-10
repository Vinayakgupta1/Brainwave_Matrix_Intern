# Password Strength Checker Tool

Welcome to the **Password Strength Checker Tool**! This tool allows users to assess the strength of passwords they enter based on criteria such as length, complexity, and uniqueness. Additionally, it includes a password generation feature to help users create strong passwords and a color-coded strength indicator for an intuitive experience.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Code Structure](#code-structure)
---

## Features

1. **Password Strength Evaluation**:
   - Checks for password length (minimum 12 characters).
   - Evaluates complexity by verifying the presence of uppercase letters, lowercase letters, digits, and special characters.
   - Analyzes common password patterns to encourage unique passwords.

2. **Color-Coded Strength Bar**:
   - Displays strength levels visually using colors (red, orange, yellow, and green) in a progress bar, making it easy to understand the strength at a glance.

3. **Password Generator**:
   - Generates strong passwords containing uppercase letters, lowercase letters, numbers, and special characters.
   - Automatically displays the generated password in the password field.

4. **Password Visibility Toggle**:
   - Allows users to show or hide the password in the entry field, providing flexibility for copying and reviewing passwords.


## Installation

To set up and run the Password Strength Checker Tool, follow these steps:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Vinayakgupta1/password-strength-checker.git
   cd password-strength-checker
   ```

2. **Install Dependencies**:
   Make sure you have Python 3 installed. Then, install the required libraries using:
   ```bash
   pip install -r requirements.txt
   ```
   *(The `requirements.txt` file should include dependencies such as `tkinter` and `re` if needed for GUI functionality.)*

3. **Run the Application**:
   Start the tool with:
   ```bash
   python password-strength-checker.py
   ```

## Usage

1. **Enter or Generate a Password**:
   - Type a password manually into the "Enter Password" field.
   - Or click on the **Generate Strong Password** button to automatically fill the field with a secure password.

2. **Check Password Strength**:
   - Click the **Check Strength** button to evaluate the password.
   - The tool will provide feedback on the password's strength and display a color-coded strength indicator.

3. **View Feedback and Strength Bar**:
   - The feedback section will show specific suggestions on improving password strength if needed.
   - The color-coded progress bar will visually indicate the strength level:
     - **Red**: Very Weak
     - **Orange**: Weak
     - **Yellow**: Moderate
     - **Green**: Strong

4. **Toggle Password Visibility**:
   - Use the "Show Password" checkbox to view or hide the password as plain text.

## How It Works

The tool evaluates passwords using the following checks:
- **Length**: Requires at least 12 characters for adequate strength.
- **Complexity**: Verifies the inclusion of uppercase letters, lowercase letters, numbers, and special characters.
- **Uniqueness**: Cross-references against a list of common passwords to ensure it’s not overly predictable.

### Color-Coded Strength Indicator
The progress bar updates based on the password score:
- **0-2**: Very Weak (Red)
- **3**: Weak (Orange)
- **4**: Moderate (Yellow)
- **5-6**: Strong (Green)

These color codes make it easy for users to understand the password's strength level at a glance.

## Code Structure

- **password_checker.py**: Contains the main code for the Password Strength Checker Tool.
- **requirements.txt**: Lists all necessary libraries for the project.
- **README.md**: This file - an interactive documentation guide for the project.
