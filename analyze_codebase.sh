#!/bin/sh

# Default output file name
OUTPUT_FILE="codebase_analysis.txt"

# Get the absolute path of the script
SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")

# Default ignore patterns for common non-code files and directories
DEFAULT_IGNORE_PATTERNS="node_modules venv .git .svn .idea .vscode __pycache__ *.pyc *.pyo *.class *.jar *.war *.ear *.zip *.tar *.gz *.rar *.exe *.dll *.so *.dylib *.bin *.obj *.o *.a *.lib *.out *.log *.sql *.sqlite *.db *.mdb *.pkl *.bak *.swp *.swo *.tmp *.temp *.DS_Store Thumbs.db *.min.js *.min.css package-lock.json yarn.lock Gemfile.lock Pipfile.lock composer.lock"

# Function to check if a file should be ignored
should_ignore() {
    file="$1"
    
    # Check if the file is the script itself or the output file
    if [ "$file" = "$SCRIPT_PATH" ] || [ "$(basename "$file")" = "$OUTPUT_FILE" ]; then
        return 0
    fi
    
    # Check if the file is in a test folder
    case "$file" in
        *"/test/"*) return 0 ;;
        *"/tests/"*) return 0 ;;
        *"/spec/"*) return 0 ;;
    esac
    
    for pattern in $DEFAULT_IGNORE_PATTERNS $ADDITIONAL_IGNORE; do
        case "$file" in
            *"$pattern"*) return 0 ;;
        esac
    done
    
    # Check if the file is binary
    if [ -f "$file" ] && file "$file" | grep -q "binary"; then
        return 0
    fi
    
    return 1
}

# Function to redact sensitive information
redact_sensitive_info() {
    sed -e 's/\(password\s*=\s*\)[^ ]*/\1[REDACTED]/gi' \
        -e 's/\(passwd\s*=\s*\)[^ ]*/\1[REDACTED]/gi' \
        -e 's/\(secret\s*=\s*\)[^ ]*/\1[REDACTED]/gi' \
        -e 's/\(api[_-]key\s*=\s*\)[^ ]*/\1[REDACTED]/gi' \
        -e 's/\(access[_-]token\s*=\s*\)[^ ]*/\1[REDACTED]/gi' \
        -e 's/\(private[_-]key\s*=\s*\)[^ ]*/\1[REDACTED]/gi' \
        -e 's/\("password"\s*:\s*"\)[^"]*"/\1[REDACTED]"/gi' \
        -e 's/\("passwd"\s*:\s*"\)[^"]*"/\1[REDACTED]"/gi' \
        -e 's/\("secret"\s*:\s*"\)[^"]*"/\1[REDACTED]"/gi' \
        -e 's/\("api[_-]key"\s*:\s*"\)[^"]*"/\1[REDACTED]"/gi' \
        -e 's/\("access[_-]token"\s*:\s*"\)[^"]*"/\1[REDACTED]"/gi' \
        -e 's/\("private[_-]key"\s*:\s*"\)[^"]*"/\1[REDACTED]"/gi'
}

# Function to process files recursively
process_directory() {
    dir="$1"
    relative_path="$2"

    # Print directory header
    echo "\n=== Directory: $relative_path ==="

    # Temporary variables to store file and directory names
    files=""
    directories=""

    for item in "$dir"/*; do
        [ -e "$item" ] || continue  # Check if item exists (handles empty directories)

        item_name=$(basename "$item")
        item_relative_path="$relative_path$item_name"
        item_absolute_path=$(realpath "$item")

        if should_ignore "$item"; then
            continue
        fi

        if [ -d "$item" ]; then
            # Add directory to the list if not already processed
            if ! echo "$PROCESSED_FILES" | grep -q "$item_absolute_path"; then
                directories="$directories\n  $item_name/"
                PROCESSED_FILES="$PROCESSED_FILES $item_absolute_path"
                process_directory "$item" "$item_relative_path/"
            fi
        elif [ -f "$item" ]; then
            # Add file to the list if not already processed
            if ! echo "$PROCESSED_FILES" | grep -q "$item_absolute_path"; then
                files="$files\n  $item_name"
                PROCESSED_FILES="$PROCESSED_FILES $item_absolute_path"
                
                echo "=== Contents of $item_relative_path ===" >> "$OUTPUT_FILE"
                cat "$item" | redact_sensitive_info >> "$OUTPUT_FILE"
                echo "\n\n" >> "$OUTPUT_FILE"
            fi
        fi
    done

    # Print directories first, then files
    if [ -n "$directories" ]; then
        echo "Directories:$directories"
    fi
    if [ -n "$files" ]; then
        echo "Files:$files"
    fi
}

# Function to perform a second pass of redaction on the output file
advanced_redaction() {
    temp_file=$(mktemp)
    cp "$OUTPUT_FILE" "$temp_file"

    # Perform redaction using individual sed commands
    sed -i '' -E 's/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}/[EMAIL REDACTED]/g' "$temp_file"
    sed -i '' -E 's/([0-9]{1,3}\.){3}[0-9]{1,3}/[IP REDACTED]/g' "$temp_file"
    sed -i '' -E 's/http[s]?:\/\/[^ ]*/[URL REDACTED]/g' "$temp_file"
    sed -i '' -E 's/[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}/[CREDIT CARD REDACTED]/g' "$temp_file"
    sed -i '' -E 's/[0-9]{3}-[0-9]{2}-[0-9]{4}/[SSN REDACTED]/g' "$temp_file"
    sed -i '' -E 's/([a-zA-Z0-9_-]+key[a-zA-Z0-9_-]*|[a-zA-Z0-9_-]*key[a-zA-Z0-9_-]+)="?[A-Za-z0-9+\/]{20,}"?/\1="[POTENTIAL API KEY REDACTED]"/g' "$temp_file"
    sed -i '' -E 's/AKIA[0-9A-Z]{16}/[AWS KEY REDACTED]/g' "$temp_file"
    sed -i '' -E 's/-----BEGIN [A-Z ]* PRIVATE KEY-----.*-----END [A-Z ]* PRIVATE KEY-----/[PRIVATE KEY REDACTED]/g' "$temp_file"
    sed -i '' -E 's/eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/[JWT REDACTED]/g' "$temp_file"
    
    mv "$temp_file" "$OUTPUT_FILE"
}

# Main execution

# Parse command line arguments
while getopts "o:i:" opt; do
  case $opt in
    o)
      OUTPUT_FILE="$OPTARG"
      ;;
    i)
      ADDITIONAL_IGNORE="$OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Clear the output file if it already exists
> "$OUTPUT_FILE"

echo "Starting analysis of current directory: $(pwd)"
process_directory "$(pwd)" "./"

echo "Performing advanced redaction on the output file..."
advanced_redaction

echo "\nAnalysis complete. Contents have been copied to $OUTPUT_FILE"