#!/bin/bash

# Get the current directory name
CURRENT_DIR=$(basename "$(pwd)")

# Default output file name
OUTPUT_FILE="java_config_analysis_${CURRENT_DIR}.txt"

# Function to check if a file is a Java configuration file
is_java_config_file() {
    file="$1"
    case "$file" in
        *.properties|*.xml|*.yaml|*.yml|*.json)
            return 0
            ;;
    esac
    return 1
}

# Function to redact sensitive information
redact_sensitive_info() {
    LC_ALL=C sed -e 's/\(password\s*=\s*\)[^ ]*/\1[REDACTED]/gi' \
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

    for item in "$dir"/*; do
        [ -e "$item" ] || continue  # Check if item exists (handles empty directories)

        item_name=$(basename "$item")
        item_relative_path="$relative_path$item_name"

        if [ -d "$item" ]; then
            process_directory "$item" "$item_relative_path/"
        elif [ -f "$item" ] && is_java_config_file "$item"; then
            echo "=== Contents of $item_relative_path ===" >> "$OUTPUT_FILE"
            LC_ALL=C cat "$item" | redact_sensitive_info >> "$OUTPUT_FILE" 2>/dev/null
            echo -e "\n\n" >> "$OUTPUT_FILE"
        fi
    done
}

# Function to perform a second pass of redaction on the output file
advanced_redaction() {
    temp_file=$(mktemp)
    cp "$OUTPUT_FILE" "$temp_file"

    # Perform redaction using individual sed commands
    LC_ALL=C sed -i '' -E 's/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}/[EMAIL REDACTED]/g' "$temp_file" 2>/dev/null
    LC_ALL=C sed -i '' -E 's/([0-9]{1,3}\.){3}[0-9]{1,3}/[IP REDACTED]/g' "$temp_file" 2>/dev/null
    LC_ALL=C sed -i '' -E 's/http[s]?:\/\/[^ ]*/[URL REDACTED]/g' "$temp_file" 2>/dev/null
    LC_ALL=C sed -i '' -E 's/[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}/[CREDIT CARD REDACTED]/g' "$temp_file" 2>/dev/null
    LC_ALL=C sed -i '' -E 's/[0-9]{3}-[0-9]{2}-[0-9]{4}/[SSN REDACTED]/g' "$temp_file" 2>/dev/null
    LC_ALL=C sed -i '' -E 's/([a-zA-Z0-9_-]+key[a-zA-Z0-9_-]*|[a-zA-Z0-9_-]*key[a-zA-Z0-9_-]+)="?[A-Za-z0-9+\/]{20,}"?/\1="[POTENTIAL API KEY REDACTED]"/g' "$temp_file" 2>/dev/null
    LC_ALL=C sed -i '' -E 's/AKIA[0-9A-Z]{16}/[AWS KEY REDACTED]/g' "$temp_file" 2>/dev/null
    LC_ALL=C sed -i '' -E 's/-----BEGIN [A-Z ]* PRIVATE KEY-----.*-----END [A-Z ]* PRIVATE KEY-----/[PRIVATE KEY REDACTED]/g' "$temp_file" 2>/dev/null
    LC_ALL=C sed -i '' -E 's/eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/[JWT REDACTED]/g' "$temp_file" 2>/dev/null
    
    mv "$temp_file" "$OUTPUT_FILE"
}

# Main execution

# Parse command line arguments
while getopts "o:" opt; do
  case $opt in
    o)
      OUTPUT_FILE="$OPTARG"
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

echo "Starting analysis of Java configuration files in current directory: $(pwd)"
process_directory "$(pwd)" "./"

echo "Performing advanced redaction on the output file..."
advanced_redaction

echo "Analysis complete. Java configuration files have been analyzed and copied to $OUTPUT_FILE"