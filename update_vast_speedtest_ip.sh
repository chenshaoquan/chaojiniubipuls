#!/bin/bash

# ============================================
# Vast.ai 测速服务器IP更新工具 (单文件版本)
# 用法: sudo ./update_vast_speedtest_ip.sh <新IP地址>
# 功能: 解除文件锁定 -> 更新IP -> 重新锁定
# ============================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否以root运行
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "请使用sudo运行此脚本"
        exit 1
    fi
}

# 检查参数
check_args() {
    if [ $# -ne 1 ]; then
        echo "用法: $0 <新的IP地址>"
        echo "示例: $0 192.168.1.100"
        echo "       $0 103.45.67.89"
        exit 1
    fi
    
    # 验证IP地址格式
    local ip="$1"
    if ! [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        print_error "IP地址格式无效: $ip"
        print_error "请使用有效的IPv4地址，如: 192.168.1.100"
        exit 1
    fi
    
    NEW_IP="$ip"
}

# 检查目标文件
check_target_file() {
    TARGET_FILE="/var/lib/vastai_kaalia/send_mach_info.py"
    
    if [ ! -f "$TARGET_FILE" ]; then
        print_error "目标文件不存在: $TARGET_FILE"
        exit 1
    fi
    
    print_info "目标文件: $TARGET_FILE"
}

# 检查chattr命令
check_chattr() {
    if ! command -v chattr &> /dev/null; then
        print_warn "未找到chattr命令，跳过文件锁定功能"
        HAS_CHATTR=false
    else
        HAS_CHATTR=true
    fi
}

# 解除文件锁定
unlock_file() {
    if [ "$HAS_CHATTR" = true ]; then
        print_info "检查文件锁定状态..."
        if lsattr "$TARGET_FILE" | grep -q "i"; then
            print_info "解除文件锁定: chattr -i $TARGET_FILE"
            chattr -i "$TARGET_FILE"
            if [ $? -eq 0 ]; then
                print_info "文件锁定已解除"
            else
                print_error "解除文件锁定失败"
                exit 1
            fi
        else
            print_info "文件未锁定，继续..."
        fi
    fi
}

# 备份原文件
backup_file() {
    BACKUP_DIR="/var/lib/vastai_kaalia/backups"
    mkdir -p "$BACKUP_DIR"
    
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="$BACKUP_DIR/send_mach_info.py.backup.$TIMESTAMP"
    
    cp "$TARGET_FILE" "$BACKUP_FILE"
    print_info "已创建备份: $BACKUP_FILE"
}

# 获取当前IP
get_current_ip() {
    # 尝试从文件中提取当前IP
    CURRENT_IP=$(grep -o "ssh_host = \"root@[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+\"" "$TARGET_FILE" 2>/dev/null | grep -o "[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+" || true)
    
    if [ -z "$CURRENT_IP" ]; then
        # 尝试查找其他格式的IP
        CURRENT_IP=$(grep -o "91\.108\.248\.213" "$TARGET_FILE" 2>/dev/null || true)
    fi
    
    if [ -n "$CURRENT_IP" ]; then
        print_info "当前测速服务器IP: $CURRENT_IP"
    else
        print_warn "未找到当前IP地址，将使用默认查找"
        CURRENT_IP="91.108.248.213"
    fi
}

# 更新IP地址
update_ip() {
    print_info "正在更新IP地址: $CURRENT_IP -> $NEW_IP"
    
    # 方法1: 替换 ssh_host = "root@IP" 格式
    sed -i "s/ssh_host = \"root@$CURRENT_IP\"/ssh_host = \"root@$NEW_IP\"/g" "$TARGET_FILE" 2>/dev/null || true
    
    # 方法2: 替换直接IP地址
    sed -i "s/$CURRENT_IP/$NEW_IP/g" "$TARGET_FILE" 2>/dev/null || true
    
    # 方法3: 如果文件中有硬编码的91.108.248.213，也替换
    sed -i "s/91\.108\.248\.213/$NEW_IP/g" "$TARGET_FILE" 2>/dev/null || true
    
    print_info "IP地址更新完成"
}

# 验证更新
verify_update() {
    print_info "验证更新结果..."
    
    if grep -q "root@$NEW_IP" "$TARGET_FILE" || grep -q "$NEW_IP" "$TARGET_FILE"; then
        print_info "✓ 验证成功: 文件中包含新IP地址 $NEW_IP"
        
        # 显示更新后的相关行
        echo -e "\n${YELLOW}更新后的相关行:${NC}"
        grep -n "ssh_host\|$NEW_IP" "$TARGET_FILE" | head -5
    else
        print_warn "⚠ 未找到新IP的引用，但更新操作已完成"
        print_warn "可能是IP格式不同，请手动检查文件"
    fi
}

# 重新锁定文件
lock_file() {
    if [ "$HAS_CHATTR" = true ]; then
        print_info "重新锁定文件: chattr +i $TARGET_FILE"
        chattr +i "$TARGET_FILE"
        
        if lsattr "$TARGET_FILE" | grep -q "i"; then
            print_info "✓ 文件已成功锁定 (immutable)"
        else
            print_warn "⚠ 文件锁定可能未生效"
        fi
    fi
}

# 显示摘要
show_summary() {
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}          更新完成摘要${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "目标文件: $TARGET_FILE"
    echo -e "旧IP地址: ${CURRENT_IP:-未找到}"
    echo -e "新IP地址: $NEW_IP"
    
    if [ "$HAS_CHATTR" = true ]; then
        echo -e "文件锁定: 已${GREEN}启用${NC} (immutable)"
    else
        echo -e "文件锁定: ${YELLOW}未启用${NC} (chattr未找到)"
    fi
    
    if [ -n "$BACKUP_FILE" ]; then
        echo -e "备份文件: $BACKUP_FILE"
    fi
    
    echo -e "${GREEN}========================================${NC}"
}

# 主函数
main() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Vast.ai 测速服务器IP更新工具${NC}"
    echo -e "${GREEN}========================================${NC}"
    
    # 检查root权限
    check_root
    
    # 检查参数
    check_args "$@"
    
    # 检查目标文件
    check_target_file
    
    # 检查chattr
    check_chattr
    
    # 解除文件锁定
    unlock_file
    
    # 备份文件
    backup_file
    
    # 获取当前IP
    get_current_ip
    
    # 更新IP地址
    update_ip
    
    # 验证更新
    verify_update
    
    # 重新锁定文件
    lock_file
    
    # 显示摘要
    show_summary
    
    echo -e "\n${GREEN}操作完成！现在可以使用新IP地址进行测速。${NC}"
}

# 运行主函数
main "$@"
