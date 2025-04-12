import subprocess
import sys
import os

def setup_environment():
    print("Setting up the environment...")
    
    # Create virtual environment if it doesn't exist
    if not os.path.exists('.venv'):
        subprocess.run([sys.executable, '-m', 'venv', '.venv'])
    
    # Activate virtual environment and install requirements
    if os.name == 'nt':  # Windows
        python_path = os.path.join('.venv', 'Scripts', 'python.exe')
        pip_path = os.path.join('.venv', 'Scripts', 'pip.exe')
    else:  # Unix/Linux
        python_path = os.path.join('.venv', 'bin', 'python')
        pip_path = os.path.join('.venv', 'bin', 'pip')
    
    print("Installing requirements...")
    subprocess.run([pip_path, 'install', '-r', 'requirements.txt'])
    
    return python_path

def run_app(python_path):
    print("Starting the Flask application...")
    subprocess.run([python_path, 'app.py'])

if __name__ == '__main__':
    python_path = setup_environment()
    run_app(python_path)
