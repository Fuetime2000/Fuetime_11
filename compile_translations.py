import os
import subprocess

def compile_translations():
    languages = ['hi', 'mr', 'gu', 'ta', 'te']
    for lang in languages:
        input_file = os.path.join('translations', lang, 'LC_MESSAGES', 'messages.po')
        output_file = os.path.join('translations', lang, 'LC_MESSAGES', 'messages.mo')
        
        if os.path.exists(input_file):
            print(f"Compiling {lang} translations...")
            try:
                subprocess.run(['pybabel', 'compile', '-d', 'translations', '-l', lang])
                print(f"Compiled {lang} translations successfully!")
            except Exception as e:
                print(f"Error compiling {lang} translations: {e}")

if __name__ == '__main__':
    compile_translations()
