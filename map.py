#map.py
#!/usr/bin/env python3
import os
import re
import sys
import shutil
from collections import defaultdict

# ------------- CONFIG -------------

# Common built-in modules to skip in requirements.txt
BUILTINS = {
    'os', 'sys', 're', 'time', 'threading', 'sqlite3', 'datetime',
    'hashlib', 'pathlib', 'subprocess', 'collections', 'glob', 'pwd',
    'random', 'string', 'typing', 'itertools', 'calendar', 'tempfile'
}

# ------------- FUNCTIONS -------------

def find_imports_and_buttons(filepath):
    local_imports = set()
    external_imports = set()
    button_connections = []

    import_regex = re.compile(r'^\s*(?:from\s+([\w\.]+)\s+import|import\s+([\w\.]+))')
    button_regex = re.compile(r'self\.(\w+)\.clicked\.connect\(self\.(\w+)\)')

    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            # Imports
            match = import_regex.match(line)
            if match:
                mod = match.group(1) or match.group(2)
                if mod:
                    base_mod = mod.split('.')[0]
                    local_file = base_mod + '.py'
                    local_imports.add(local_file)
                    external_imports.add(base_mod)
            # Buttons
            bmatch = button_regex.search(line)
            if bmatch:
                button_name = bmatch.group(1)
                callback_name = bmatch.group(2)
                button_connections.append((button_name, callback_name))

    return local_imports, external_imports, button_connections

def gather_top_level_py_files(project_dir):
    py_files = set()
    for file in os.listdir(project_dir):
        if file.endswith('.py') and os.path.isfile(os.path.join(project_dir, file)):
            py_files.add(file)
    return py_files

def resolve_import_tree(entry_file, project_dir):
    all_py_files = gather_top_level_py_files(project_dir)
    import_tree = defaultdict(list)
    external_imports_all = set()
    button_map = {}

    processed = set()
    to_process = [entry_file]

    while to_process:
        current = to_process.pop()
        if current in processed:
            continue
        processed.add(current)

        current_path = os.path.join(project_dir, current)
        if not os.path.isfile(current_path):
            continue

        local_imports, external_imports, button_connections = find_imports_and_buttons(current_path)
        external_imports_all.update(external_imports)

        if button_connections:
            button_map[current] = button_connections

        for imp in local_imports:
            if imp in all_py_files:
                import_tree[current].append(imp)
                if imp not in processed:
                    to_process.append(imp)

    return import_tree, processed, external_imports_all, button_map

def print_import_tree(import_tree, button_map, entry_file, indent='', output_lines=None):
    line = f"{indent}{entry_file}"
    print(line)
    if output_lines is not None:
        output_lines.append(line)

    # If this file has button connections, print them
    if entry_file in button_map:
        for button_name, callback in button_map[entry_file]:
            btn_line = f"{indent}    Button: {button_name} → {callback}"
            print(btn_line)
            if output_lines is not None:
                output_lines.append(btn_line)

    # Now print child imports
    children = import_tree.get(entry_file, [])
    for i, child in enumerate(children):
        is_last = (i == len(children) - 1)
        connector = '└── ' if is_last else '├── '
        new_indent = indent + ('    ' if is_last else '│   ')
        line = f"{indent}{connector}{child}"
        print(line)
        if output_lines is not None:
            output_lines.append(line)
        print_import_tree(import_tree, button_map, child, new_indent, output_lines)

def move_unused_files(project_dir, used_files):
    not_used_dir = os.path.join(project_dir, 'not_used')
    os.makedirs(not_used_dir, exist_ok=True)

    all_py_files = gather_top_level_py_files(project_dir)

    for py_file in all_py_files:
        if py_file == 'map.py':
            continue  # Never move map.py!
        if py_file not in used_files:
            src = os.path.join(project_dir, py_file)
            dst = os.path.join(not_used_dir, py_file)
            print(f"Moving unused file: {py_file} -> not_used/{py_file}")
            shutil.move(src, dst)

def write_map_txt(project_dir, map_lines):
    map_path = os.path.join(project_dir, 'map.txt')
    with open(map_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(map_lines))
    print(f"\n🗺️  map.txt written: {map_path}")

def write_requirements_txt(project_dir, external_imports, local_py_files):
    clean_reqs = []
    for imp in sorted(external_imports):
        if (imp + '.py') in local_py_files:
            continue
        if imp in BUILTINS:
            continue
        clean_reqs.append(imp)

    req_path = os.path.join(project_dir, 'requirements.txt')
    with open(req_path, 'w', encoding='utf-8') as f:
        for req in clean_reqs:
            f.write(req + '\n')
    print(f"\n📦 requirements.txt written: {req_path}")

# ------------- MAIN -------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 map.py path/to/main.py")
        sys.exit(1)

    entry_path = os.path.abspath(sys.argv[1])
    project_dir = os.path.dirname(entry_path)
    entry_file = os.path.basename(entry_path)

    print(f"\n📂 Project directory: {project_dir}")
    print(f"🚀 Entry script: {entry_file}")

    import_tree, used_files, external_imports, button_map = resolve_import_tree(entry_file, project_dir)

    print("\n📚 Dependency tree (with button map!):\n")
    map_lines = []
    print_import_tree(import_tree, button_map, entry_file, output_lines=map_lines)

    print(f"\n✅ Used files ({len(used_files)} total):")
    for f in sorted(used_files):
        print(f"  - {f}")

    move_unused_files(project_dir, used_files)

    write_map_txt(project_dir, map_lines)
    write_requirements_txt(project_dir, external_imports, gather_top_level_py_files(project_dir))

    print("\n🎉 Done! map.txt + requirements.txt created. Unused files moved.\n")

# ------------- RUN -------------

if __name__ == "__main__":
    main()
