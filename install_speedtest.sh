#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  VPS 测速服务器 IP 修改工具${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# 目标文件路径
TARGET_FILE="/var/lib/vastai_kaalia/send_mach_info.py"

# 检查目标文件是否存在
if [ ! -f "$TARGET_FILE" ]; then
    echo -e "${RED}错误: 文件 $TARGET_FILE 不存在${NC}"
    exit 1
fi

# 检查是否通过命令行参数传入 IP
if [ -n "$1" ]; then
    NEW_VPS_IP="$1"
    echo -e "${YELLOW}使用命令行参数指定的 VPS IP: ${NEW_VPS_IP}${NC}"
else
    # 交互式输入 VPS IP 地址
    read -p "请输入新的 VPS 测速服务器 IP 地址 (默认: 206.206.78.250): " NEW_VPS_IP </dev/tty
    NEW_VPS_IP=${NEW_VPS_IP:-206.206.78.250}
    echo -e "${YELLOW}使用的 VPS IP: ${NEW_VPS_IP}${NC}"
fi
echo ""

# 显示当前配置的 IP
echo -e "${YELLOW}正在检查当前配置...${NC}"
CURRENT_IP=$(grep -oP 'def remote_speedtest_via_vps\(vps_host="\K[^"]+' "$TARGET_FILE" 2>/dev/null || echo "未找到")
echo -e "当前 VPS IP: ${YELLOW}${CURRENT_IP}${NC}"
echo -e "新的 VPS IP: ${GREEN}${NEW_VPS_IP}${NC}"
echo ""

# 备份原文件
echo -e "${YELLOW}正在备份原文件...${NC}"
BACKUP_FILE="${TARGET_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
sudo cp "$TARGET_FILE" "$BACKUP_FILE"
echo -e "${GREEN}备份完成: ${BACKUP_FILE}${NC}"
echo ""

# 解锁文件
echo -e "${YELLOW}正在解锁文件...${NC}"
sudo chattr -i "$TARGET_FILE" 2>/dev/null || true

# 替换 IP 地址（两处位置）
echo -e "${YELLOW}正在修改 IP 地址...${NC}"

# 1. 替换函数定义中的默认 IP
sudo sed -i "s/def remote_speedtest_via_vps(vps_host=\"[^\"]*\"/def remote_speedtest_via_vps(vps_host=\"${NEW_VPS_IP}\"/" "$TARGET_FILE"

# 2. 替换 argparse 中的默认 IP
sudo sed -i "s/--vps-host.*default=\"[^\"]*\"/--vps-host\", action='store', default=\"${NEW_VPS_IP}\"/" "$TARGET_FILE"

# 验证修改
VERIFY_IP=$(grep -oP 'def remote_speedtest_via_vps\(vps_host="\K[^"]+' "$TARGET_FILE" 2>/dev/null || echo "验证失败")
if [ "$VERIFY_IP" = "$NEW_VPS_IP" ]; then
    echo -e "${GREEN}✓ IP 地址修改成功${NC}"
else
    echo -e "${RED}✗ IP 地址修改可能失败，请检查${NC}"
fi
echo ""

# 锁定文件
echo -e "${YELLOW}正在锁定文件...${NC}"
sudo chattr +i "$TARGET_FILE"
echo -e "${GREEN}文件已锁定${NC}"
echo ""

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  修改完成！${NC}"
echo -e "${GREEN}================================${NC}"
echo -e "文件路径: ${YELLOW}$TARGET_FILE${NC}"
echo -e "新 VPS IP: ${GREEN}$NEW_VPS_IP${NC}"
echo -e "备份文件: ${YELLOW}$BACKUP_FILE${NC}"
echo ""
echo -e "${YELLOW}提示：${NC}"
echo -e "- 如需解锁文件，运行: ${GREEN}sudo chattr -i $TARGET_FILE${NC}"
echo -e "- 如需恢复备份，运行: ${GREEN}sudo cp $BACKUP_FILE $TARGET_FILE${NC}"
echo ""
