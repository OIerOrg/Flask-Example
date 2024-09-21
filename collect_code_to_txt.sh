#!/bin/bash

# 定义要查找的代码文件扩展名
EXTENSIONS=("py" "java" "c" "cpp" "js" "html" "ts" "rb" "go" "php" "swift" "kt" "rs" "sh" "pl" "sql")

# 输出文件
OUTPUT_FILE="project_code.txt"

# 清空输出文件（如果已存在）
> "$OUTPUT_FILE"

# 定义要排除的目录（如 venv）
EXCLUDE_DIRS=("venv" "__pycache__" ".git" "node_modules")  # 可根据需要添加更多要排除的目录

# 开始构建 find 命令
FIND_CMD=(find .)

# 添加排除目录的参数
for dir in "${EXCLUDE_DIRS[@]}"; do
    FIND_CMD+=( -path "./$dir" -prune -o )
done

# 添加文件名匹配条件
FIND_CMD+=( -type f \( )
FIRST=true
for ext in "${EXTENSIONS[@]}"; do
    if [ "$FIRST" = true ]; then
        FIND_CMD+=( -name "*.$ext" )
        FIRST=false
    else
        FIND_CMD+=( -o -name "*.$ext" )
    fi
done
FIND_CMD+=( \) -print )

# 执行 find 命令并处理找到的文件
"${FIND_CMD[@]}" | while read -r file; do
    echo "===== 文件: $file =====" >> "$OUTPUT_FILE"
    cat "$file" >> "$OUTPUT_FILE"
    echo -e "\n\n" >> "$OUTPUT_FILE"
done

echo "所有代码文件（已排除指定目录）已合并到 ${OUTPUT_FILE}"
