# Contributing to PassM

Thank you for your interest in contributing! Please follow these guidelines to ensure code quality and security.

## Coding Standards

- Follow [PEP 8](https://peps.python.org/pep-0008/) for Python code style.
- Use strong encryption from the `cryptography` library for all sensitive data.
- Validate all user input and handle errors securely.
- Avoid hardcoding secrets or credentials in code.
- Write clear, descriptive comments and docstrings.
- Ensure cross-platform compatibility (Windows, Linux, macOS).

## Setup Instructions

1. Install Python 3.8 or newer.
2. Clone the repository: `git clone <repo-url>`
3. Navigate to the project directory: `cd PassM`
4. Create a virtual environment:
   - Windows: `python -m venv .venv`
   - Linux/macOS: `python3 -m venv .venv`
5. Activate the virtual environment:
   - Windows: `.venv\Scripts\activate`
   - Linux/macOS: `source .venv/bin/activate`
6. Install dependencies: `pip install -r requirements.txt`
7. Run the application: `python password_manager.py`

## Submitting Changes

- Fork the repository and create a new branch for your feature or fix.
- Test your changes thoroughly.
- Submit a pull request with a clear description of your changes.

## Security

- Report vulnerabilities or security concerns via issues or direct contact.
- Do not share sensitive information in public channels.
