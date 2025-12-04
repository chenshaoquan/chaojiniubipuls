#!/bin/bash
# 远程测速自动安装脚本
# 用途：将 send_mach_info.py 修改为使用远程 VPS 测速
# 作者：自动覆盖测速项目
# 使用方法：curl -sSL https://raw.githubusercontent.com/chenshaoquan/chaojiniubipuls/main/install_remote_speedtest.sh | bash

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置文件路径
TARGET_FILE="/var/lib/vastai_kaalia/send_mach_info.py"
BACKUP_DIR="/var/lib/vastai_kaalia/backups"
CONFIG_FILE="/var/lib/vastai_kaalia/.remote_speedtest_config"

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否以 root 运行
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "请使用 root 权限运行此脚本"
        echo "使用方法: sudo bash $0"
        exit 1
    fi
}

# 检查目标文件是否存在
check_target_file() {
    if [ ! -f "$TARGET_FILE" ]; then
        print_error "目标文件不存在: $TARGET_FILE"
        exit 1
    fi
    print_success "找到目标文件: $TARGET_FILE"
}

# 读取或输入测速服务器地址
get_speedtest_server() {
    local current_server=""
    
    # 检查是否已经配置过
    if [ -f "$CONFIG_FILE" ]; then
        current_server=$(cat "$CONFIG_FILE" 2>/dev/null || echo "")
        if [ -n "$current_server" ]; then
            print_info "当前配置的测速服务器: ${GREEN}$current_server${NC}"
            read -p "是否使用此服务器？(Y/n): " use_current
            if [[ "$use_current" =~ ^[Nn]$ ]]; then
                current_server=""
            else
                SPEEDTEST_SERVER="$current_server"
                return 0
            fi
        fi
    fi
    
    # 输入新的服务器地址
    while true; do
        echo ""
        read -p "请输入测速服务器 IP 地址或域名: " server_input
        
        if [ -z "$server_input" ]; then
            print_warning "服务器地址不能为空"
            continue
        fi
        
        # 验证 IP 地址或域名格式
        if [[ "$server_input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$server_input" =~ ^[a-zA-Z0-9.-]+$ ]]; then
            SPEEDTEST_SERVER="$server_input"
            print_success "测速服务器设置为: $SPEEDTEST_SERVER"
            
            # 保存配置
            echo "$SPEEDTEST_SERVER" > "$CONFIG_FILE"
            chmod 600 "$CONFIG_FILE"
            break
        else
            print_error "无效的 IP 地址或域名格式"
        fi
    done
}

# 测试 SSH 连接
test_ssh_connection() {
    print_info "测试 SSH 连接到 $SPEEDTEST_SERVER..."
    
    if timeout 10 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@"$SPEEDTEST_SERVER" 'echo "SSH OK"' &>/dev/null; then
        print_success "SSH 连接测试成功"
        return 0
    else
        print_warning "SSH 连接测试失败（这不会阻止安装，但可能需要配置 SSH 密钥）"
        print_info "建议运行: ssh-copy-id root@$SPEEDTEST_SERVER"
        read -p "是否继续安装？(Y/n): " continue_install
        if [[ "$continue_install" =~ ^[Nn]$ ]]; then
            exit 1
        fi
        return 1
    fi
}

# 创建备份
create_backup() {
    print_info "创建备份..."
    
    # 创建备份目录
    mkdir -p "$BACKUP_DIR"
    
    # 备份文件名包含时间戳
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/send_mach_info.py.backup_$timestamp"
    
    # 解锁文件（如果已锁定）
    chattr -i "$TARGET_FILE" 2>/dev/null || true
    
    # 复制备份
    cp "$TARGET_FILE" "$backup_file"
    
    print_success "备份已创建: $backup_file"
    
    # 保留最近 5 个备份
    ls -t "$BACKUP_DIR"/send_mach_info.py.backup_* 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
}

# 检查文件是否已经修改过
check_if_already_modified() {
    if grep -q "def remote_speedtest_via_vps" "$TARGET_FILE" 2>/dev/null; then
        print_warning "检测到文件已经包含远程测速功能"
        return 0
    fi
    return 1
}

# 生成修改后的 Python 文件内容
generate_modified_file() {
    print_info "生成修改后的文件内容..."
    
    # 读取原文件内容
    local original_content=$(cat "$TARGET_FILE")
    
    # 创建临时文件
    local temp_file=$(mktemp)
    
    # 写入修改后的内容
    cat > "$temp_file" << 'PYTHON_FILE_START'
#!/usr/bin/python3
import json
import subprocess
import requests
import random
import os
import subprocess
import platform
import time
from argparse import ArgumentParser

from datetime import datetime


from pathlib import Path
import re

CLK_TCK = os.sysconf(os.sysconf_names.get("SC_CLK_TCK", "SC_CLK_TCK"))
NCPU = os.cpu_count() or 1

# Patterns that indicate the process is in a containerized cgroup (Docker/containerd/K8s/Podman)
CGROUP_CONTAINER_PAT = re.compile(r"(docker|containerd|kubepods|libpod)", re.IGNORECASE)


def read_proc_stat_cpu():
    """
    Read the aggregated CPU times from /proc/stat.
    Returns (total_jiffies, idle_jiffies).
    """
    with open("/proc/stat", "r") as f:
        for line in f:
            if line.startswith("cpu "):
                parts = line.split()
                # cpu user nice system idle iowait irq softirq steal guest guest_nice
                # Use standard kernel accounting: total is sum of first 8 fields (user..steal)
                # idle time is idle + iowait
                # Some kernels have fewer/more fields; guard accordingly.
                values = [int(x) for x in parts[1:]]
                # Ensure length >= 8
                while len(values) < 8:
                    values.append(0)
                user, nice, system, idle, iowait, irq, softirq, steal = values[:8]
                idle_all = idle + iowait
                total = user + nice + system + idle + iowait + irq + softirq + steal
                return total, idle_all
    # Fallback if cpu line missing (shouldn't happen on Linux)
    return 0, 0


def list_pids():
    for name in os.listdir("/proc"):
        if name.isdigit():
            yield name


def pid_in_container(pid):
    """
    Heuristic: check /proc/<pid>/cgroup entries for container-runtime markers.
    """
    try:
        with open(f"/proc/{pid}/cgroup", "r") as f:
            data = f.read()
        return bool(CGROUP_CONTAINER_PAT.search(data))
    except Exception:
        return False


def pid_utime_stime_jiffies(pid):
    """
    Return utime + stime for a process, in jiffies.
    We do not add children's times to avoid double counting when summing across PIDs.
    """
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            stat = f.read().split()
        # utime is field 14, stime is field 15 (1-indexed in manpage; 0-indexed here -> 13,14)
        utime = int(stat[13])
        stime = int(stat[14])
        return utime + stime
    except Exception:
        return 0


def sample_process_cpu_split():
    """
    Sum utime+stime across all PIDs, split by (inside_container vs outside).
    Returns tuple (sum_in_docker_jiffies, sum_outside_jiffies).
    """
    in_docker = 0
    outside = 0
    for pid in list_pids():
        j = pid_utime_stime_jiffies(pid)
        if j == 0:
            # could be kernel thread or permission error; skip quietly
            continue
        if pid_in_container(pid):
            in_docker += j
        else:
            outside += j
    return in_docker, outside


def disable_unattended_upgrades():
    subprocess.run(["sudo", "systemctl", "status", "unattended-upgrades"], check=True) #INFO: doesn't throw if enabled
    subprocess.run(["sudo", "systemctl", "stop", "unattended-upgrades"], check=True) #INFO: stop the current running systemd unit
    subprocess.run(["sudo", "systemctl", "mask", "unattended-upgrades"], check=True) #INFO: Mask systemd service so it doesn't ever try running again via restart systemd unit or rebooting machine on an enabled service



def compute_total_busy_pct(t0_total, t0_idle, t1_total, t1_idle):
    total_delta = max(1, t1_total - t0_total)
    idle_delta = max(0, t1_idle - t0_idle)
    busy_delta = max(0, total_delta - idle_delta)
    # busy fraction across all cores; normalized to 0..100
    return (busy_delta / total_delta) * 100.0


def iommu_groups():
    return Path('/sys/kernel/iommu_groups').glob('*') 
def iommu_groups_by_index():
    return ((int(path.name) , path) for path in iommu_groups())

class PCI:
    def __init__(self, id_string):
        parts: list[str] = re.split(r':|\.', id_string)
        if len(parts) == 4:
            PCI.domain = int(parts[0], 16)
            parts = parts[1:]
        else:
            PCI.domain = 0
        assert len(parts) == 3
        PCI.bus = int(parts[0], 16)
        PCI.device = int(parts[1], 16)
        PCI.fn = int(parts[2], 16)
        
# returns an iterator of devices, each of which contains the list of device functions.  
def iommu_devices(iommu_path : Path):
    paths = (iommu_path / "devices").glob("*")
    devices= {}
    for path in paths:
        pci = PCI(path.name)
        device = (pci.domain, pci.bus,pci.device)
        if device in devices:
            devices[device].append((pci,path))
        else:
            devices[device] = [(pci,path)]
    return devices

# given a list of device function IDs belonging to a device and their paths, 
# gets the render_node if it has one, using a list as an optional
def render_no_if_gpu(device_fns):
    for (_, path) in device_fns:
        if (path / 'drm').exists():
            return [r.name for r in (path/'drm').glob("render*")]
    return []

# returns a dict of bus:device -> (all pci ids, renderNode) for all gpus in an iommu group, by iommu group 
def gpus_by_iommu_by_index():
    iommus = iommu_groups_by_index()
    for index,path in iommus:
        devices = iommu_devices(path)
        gpus= {}
        for d in devices:
            gpu_m = render_no_if_gpu(devices[d])
            if gpu_m:
                gpus[d] = (devices[d], gpu_m[0])
        if len(gpus) > 0:
            yield (index,gpus)

def devices_by_iommu_by_index():
    iommus = iommu_groups_by_index()
    devices = {}
    for index,path in iommus:
        devices[index] = iommu_devices(path)
    return devices

# check if each iommu group has only one gpu
def check_if_iommu_ok(iommu_gpus, iommu_devices):
    has_iommu_gpus = False
    for (index, gpus) in iommu_gpus:
        group_has_iommu_gpus = False
        has_iommu_gpus = True
        if len(iommu_devices[index]) > 1:
            for pci_address in iommu_devices[index]:
                # check if device is gpu itself
                if pci_address in gpus:
                    if group_has_iommu_gpus:
                        return False
                    group_has_iommu_gpus = True
                    continue
                # else, check if device is bridge
                for (pci_fn, path) in iommu_devices[index][pci_address]:
                    try:
                        pci_class = subprocess.run(
                            ['sudo', 'cat', path / 'class'],
                            capture_output=True,
                            text=True,
                            check=True
                        )
                        # bridges have class 06, class is stored in hex fmt, so 0x06XXXX should be fine to pass along w/ group
                        if pci_class.stdout[2:4] != '06':
                            return False
                    except Exception as e:
                        print(f"An error occurred: {e}")
                        return False
    try:
        result = subprocess.run(
            ['sudo', 'cat', '/sys/module/nvidia_drm/parameters/modeset'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout[0] == 'N' and has_iommu_gpus
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def has_active_vast_volumes():
    result = subprocess.run(["docker", "volume", "ls", "--format", "{{.Name}}"], capture_output=True, text=True)

    try:
        for line in result.stdout.splitlines():
            if "V." in line:
                return True
    except Exception as e:
        print("An Error Occured:", e)
        pass

    return False

def check_volumes_xfs_quota():
    quota_amounts = {}
    result = subprocess.run(["sudo", "xfs_quota", "-x", "-c", "report -p -N", "/var/lib/docker"], capture_output=True)
    lines = result.stdout.decode().split('\n')
    vast_volume_lines = [line for line in lines if line.strip().startswith('V.')]

    for vast_volume_line in vast_volume_lines:
        volume_name, volume_quota = parse_vast_quota(vast_volume_line)
        quota_amounts[volume_name] = volume_quota

    return quota_amounts

#INFO: returns a tuple of volume name and the quota amount in Kib
def parse_vast_quota(vast_volume_line):
    split_lines = vast_volume_line.split(" ")
    filtered_split_lines = [line for line in split_lines if line != ""]

    return filtered_split_lines[0], int(filtered_split_lines[3])

def numeric_version(version_str):
    try:
        # Split the version string by the period
        try:
            major, minor, patch = version_str.split('.')
        except:
            major, minor = version_str.split('.')
            patch = ''

        # Pad each part with leading zeros to make it 3 digits
        major = major.zfill(3)
        minor = minor.zfill(3)
        patch = patch.zfill(3)

        # Concatenate the padded parts
        numeric_version_str = f"{major}{minor}{patch}"

        # Convert the concatenated string to an integer
        return int(numeric_version_str)

    except ValueError:
        print("Invalid version string format. Expected format: X.X.X")
        return None

def get_nvidia_driver_version():
    try:
        # Run the nvidia-smi command and capture its output
        output = subprocess.check_output(['nvidia-smi'], stderr=subprocess.STDOUT, text=True)

        # Split the output by lines
        lines = output.strip().split('\n')

        # Loop through each line and search for the driver version
        for line in lines:
            if "Driver Version" in line:
                # Extract driver version
                version_info = line.split(":")[1].strip()
                vers = version_info.split(" ")[0]
                return numeric_version(vers)

    except subprocess.CalledProcessError:
        print("Error: Failed to run nvidia-smi.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return None


def cond_install(package, extra=None):
    result = False
    location = ""
    try:
        location = subprocess.check_output(f"which {package}", shell=True).decode('utf-8').strip()
        print(location)
    except:
        pass

    if (len(location) < 1):
        print(f"installing {package}")
        output = None
        try:
            if (extra is not None):
                output  = subprocess.check_output(extra, shell=True).decode('utf-8')
            output  = subprocess.check_output(f"sudo apt install -y {package}", shell=True).decode('utf-8')
            result = True
        except:
            print(output)
    else:
        result = True
    return result

def find_drive_of_mountpoint(target):
    output = subprocess.check_output("lsblk -sJap",  shell=True).decode('utf-8')
    jomsg = json.loads(output)
    blockdevs = jomsg.get("blockdevices", [])
    mountpoints = None
    devname = None
    for bdev in blockdevs:
        mountpoints = bdev.get("mountpoints", [])
        if (not mountpoints):
            # for ubuntu version < 22.04
            mountpoints = [bdev.get("mountpoint", None)]
        if (target in mountpoints):
            devname = bdev.get("name", None)
            nextn = bdev
            while nextn is not None:
                devname = nextn.get("name", None)
                try:
                    nextn = nextn.get("children",[None])[0]
                except:
                    nextn = None
    return devname

def remote_speedtest_via_vps(vps_host="SPEEDTEST_SERVER_PLACEHOLDER", vps_port=22, vps_user="root"):
    """
    通过远程 VPS 执行测速，返回测速结果 JSON
    """
    try:
        # 在 VPS 上执行 speedtest 命令
        ssh_command = (
            f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "
            f"{vps_user}@{vps_host} "
            f"'docker run --rm vastai/test:speedtest --accept-license --accept-gdpr --format=json'"
        )
        
        print(f"Running speedtest via VPS {vps_host}...")
        output = subprocess.check_output(ssh_command, shell=True, timeout=60).decode('utf-8')
        
        # 验证 JSON 格式
        joutput = json.loads(output)
        print(f"Remote speedtest completed successfully")
        return output
        
    except subprocess.TimeoutExpired:
        print(f"Timeout connecting to VPS {vps_host}")
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error executing speedtest on VPS: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Invalid JSON response from VPS: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error in remote speedtest: {e}")
        return None


def epsilon_greedyish_speedtest():
    def epsilon(greedy):
        subprocess.run(["mkdir", "-p", "/var/lib/vastai_kaalia/.config"])
        output  = subprocess.check_output("docker run --rm -v /var/lib/vastai_kaalia/.config:/root/.config vastai/test:speedtest -L --accept-license --accept-gdpr --format=json", shell=True).decode('utf-8')
        mirrors = [server["id"] for server in json.loads(output)["servers"]]
        mirror = mirrors[random.randint(0,len(mirrors)-1)]
        print(f"running speedtest on random server id {mirror}")
        output = subprocess.check_output(f"docker run --rm -v /var/lib/vastai_kaalia/.config:/root/.config vastai/test:speedtest -s {mirror} --accept-license --accept-gdpr --format=json", shell=True).decode('utf-8')
        joutput = json.loads(output)
        score = joutput["download"]["bandwidth"] + joutput["upload"]["bandwidth"] 
        if int(score) > int(greedy):
            with open("/var/lib/vastai_kaalia/data/speedtest_mirrors", "w") as f:
                f.write(f"{mirror},{score}")
        return output
    def greedy(id):
        print(f"running speedtest on known best server id {id}")
        output = subprocess.check_output(f"docker run --rm -v /var/lib/vastai_kaalia/.config:/root/.config vastai/test:speedtest -s {id} --accept-license --accept-gdpr --format=json", shell=True).decode('utf-8')
        joutput = json.loads(output)
        score = joutput["download"]["bandwidth"] + joutput["upload"]["bandwidth"] 
        with open("/var/lib/vastai_kaalia/data/speedtest_mirrors", "w") as f: # we always want to update best in case it gets worse
            f.write(f"{id},{score}")
        return output
    try:
        with open("/var/lib/vastai_kaalia/data/speedtest_mirrors") as f:
            id, score = f.read().split(',')[0:2]
        if random.randint(0,2):
            return greedy(id)
        else:
            return epsilon(score)
    except:
        return epsilon(0)
                
def is_vms_enabled():
    try: 
        with open('/var/lib/vastai_kaalia/kaalia.cfg') as conf:
            for field in conf.readlines():
                entries = field.split('=')
                if len(entries) == 2 and entries[0].strip() == 'gpu_type' and entries[1].strip() == 'nvidia_vm':
                    return True
    except:
        pass
    return False


def get_container_start_times():
    # Run `docker ps -q` to get all running container IDs
    result = subprocess.run(["docker", "ps", "-q"], capture_output=True, text=True)
    container_ids = result.stdout.splitlines()

    containerName_to_startTimes = {}
    for container_id in container_ids:
        # Run `docker inspect` for each container to get details
        inspect_result = subprocess.run(["docker", "inspect", container_id], capture_output=True, text=True)

        container_info = json.loads(inspect_result.stdout)
        
        container_name = container_info[0]["Name"].strip("/")
        start_time = container_info[0]["State"]["StartedAt"]

        # Convert date time to unix timestamp for easy storage and computation
        dt = datetime.strptime(start_time[:26], "%Y-%m-%dT%H:%M:%S.%f")
        containerName_to_startTimes[container_name] = dt.timestamp()

    return containerName_to_startTimes
def dict_to_fio_ini(job_dict):
    lines = []
    for section, options in job_dict.items():
        lines.append(f"[{section}]")
        for key, value in options.items():
            lines.append(f"{key}={value}")
        lines.append("")
    return "\n".join(lines)
def measure_read_bandwidth(disk_path, path, size_gb=1, block_size="4M"):
    try:
        with open(disk_path, "wb") as f:
            written = 0 
            total_bytes = size_gb * 1024**3
            chunk_size = 1024**2
            while written < total_bytes:
                to_write = min(chunk_size, total_bytes - written)
                f.write(os.urandom(to_write))
                written += to_write
        job = {
            "global": {
                "ioengine": "libaio",
                "direct": 0,
                "bs": block_size,
                "size": f"{size_gb}G",
                "readwrite": "read",
                "directory": path,
                "filename" : "readtest",
                "numjobs": 1,
                "group_reporting": 1
            },
            "readtest": {
                "name": "readtest"
            }
        }
        job_file_content = dict_to_fio_ini(job)
        result = subprocess.run(
            ["sudo", "fio", "--output-format=json", "-"],
            input=job_file_content,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if result.returncode != 0:
            raise RuntimeError(f"fio failed: {result.stderr.strip()}")

        output = json.loads(result.stdout)
        bw_bytes = output["jobs"][0]["read"]["bw_bytes"]
        bw_mib = bw_bytes / (1024 * 1024)
        print(f"Read bandwidth: {bw_mib:.2f} MiB/sec")
        return bw_mib
    finally:
        os.remove(disk_path)

def mount_fuse(size, disk_mountpoint, fs_mountpoint, timeout=10):
    os.makedirs(disk_mountpoint, exist_ok=True)
    os.makedirs(fs_mountpoint, exist_ok=True)
    mounted = False
    if is_mounted(fs_mountpoint):
        mounted = True 
        try:
            subprocess.run(["sudo", "fusermount", "-u", fs_mountpoint], check=True)
            print(f"Unmounted {fs_mountpoint}")
        except subprocess.CalledProcessError as e:
            print(f"{e}")
            print(f"Could not unmount mounted FS at {fs_mountpoint}! Not running bandwidth test")
            return
    if mounted:
        # Confirm unmount
        for _ in range(20):
            if not is_mounted(fs_mountpoint):
                mounted = False
                break
            time.sleep(0.1)
    if mounted:
        print(f"Could not unmount mounted FS at {fs_mountpoint}! Not running bandwidth test")
        return

    fuse_location = "/var/lib/vastai_kaalia/vast_fuse"
    cmd_args = [
        "sudo",
        fuse_location, 
        "-m",
        disk_mountpoint,
        "-q",
        str(size),
        "--",
        "-o",
        "allow_other",
        fs_mountpoint
    ]
    proc = subprocess.Popen(
        cmd_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    start_time = time.time()
    while time.time() - start_time < timeout:
        if is_mounted(fs_mountpoint):
            return proc
        time.sleep(0.2)
    print("Timeout reached waiting for fs to mount, killing FUSE process")
    # Timeout reached
    proc.terminate()

def is_mounted(path):
    """Check if path is a mount point."""
    try:
        subprocess.run(
            ["sudo", "mountpoint", "-q", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def parse_cpu_stats():
    # First snapshot
    t0_total, t0_idle = read_proc_stat_cpu()
    d0_in, d0_out = sample_process_cpu_split()
    wall0 = time.time()

    # Sleep ~interval
    time.sleep(0.1)

    # Second snapshot
    t1_total, t1_idle = read_proc_stat_cpu()
    d1_in, d1_out = sample_process_cpu_split()
    wall1 = time.time()

    elapsed = max(1e-6, wall1 - wall0)

    total_pct = compute_total_busy_pct(t0_total, t0_idle, t1_total, t1_idle)

    # Convert jiffies deltas to "CPU capacity" consumed, normalize to percent
    delta_in_j = max(0, d1_in - d0_in)
    # outside processes' direct measurement (optional; we prefer computing outside as total - docker to avoid drift)
    # delta_out_j = max(0, d1_out - d0_out)

    docker_pct = (delta_in_j / (CLK_TCK * elapsed * NCPU)) * 100.0

    # outside as residual; clamp to [0, 100]
    outside_pct = max(0.0, min(100.0, total_pct - docker_pct))

    # Also clamp docker and total into [0,100] to be safe on jittery machines
    total_pct = max(0.0, min(100.0, total_pct))
    docker_pct = max(0.0, min(100.0, docker_pct))

    return total_pct, docker_pct, outside_pct

def get_channel():
    try: 
        with open('/var/lib/vastai_kaalia/.channel') as f:
            channel = f.read()
            return channel
    except:
        pass
    return "" # default channel is just "" on purpose.


def get_used_disk_space_gb(path: str) -> int:
    command = f"df --output=used -BG {path} | tail -n1 | awk " + "'{print $1}'"
    return int(subprocess.check_output(command, shell=True).decode("utf-8").strip()[:-1])


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("--speedtest", action='store_true')
    parser.add_argument("--server", action='store', default="https://console.vast.ai")
    parser.add_argument("--nw-disk", action='store_true')
    parser.add_argument("--vps-host", action='store', default="SPEEDTEST_SERVER_PLACEHOLDER", help="VPS host for remote speedtest")
    parser.add_argument("--vps-user", action='store', default="root", help="VPS SSH user")
    parser.add_argument("--local-speedtest", action='store_true', help="Force local speedtest instead of remote")
    args = parser.parse_args()
    output = None
    try:
        r = random.randint(0, 5)
        #print(r)
        if r == 3:
            print("apt update")
            output  = subprocess.check_output("sudo apt update", shell=True).decode('utf-8')
    except:
        print(output)


    with open('/var/lib/vastai_kaalia/machine_id', 'r') as f:
        mach_api_key = f.read()

    if has_active_vast_volumes():
        payload = {
            "mach_api_key": mach_api_key.strip(),
        }

        #INFO: these are the verified quotas
        response = requests.get(args.server+"/api/v0/machine/volume_info/", json=payload).json()

        if response["success"]:
            oracle_vast_volumes_to_disk_quotas = response["results"]
            vast_volumes_to_xfs_quota_amounts = check_volumes_xfs_quota()

            for vast_volume, vast_volume_xfs_quota in vast_volumes_to_xfs_quota_amounts.items():
                try:
                    oracle_quota = oracle_vast_volumes_to_disk_quotas.get(vast_volume)
                    #INFO: if the quota is correct, we can move on or if the quota is still around for a deleted volume
                    if not oracle_quota or oracle_quota == vast_volume_xfs_quota:
                        continue

                    oracle_quota_in_kib = oracle_quota * 1024 * 1024
                    subprocess.run(["sudo", "xfs_quota", "-x", "-c", 
                                    f"limit -p bsoft={oracle_quota_in_kib}K bhard={oracle_quota_in_kib}K {vast_volume}",
                                    "/var/lib/docker/"], check=True)
                except Exception as e:
                    print(f"An error occurred: {e}")



    # Command to get disk usage in GB
    print(datetime.now())

    print('os version')
    cmd = "lsb_release -a 2>&1 | grep 'Release:' | awk '{printf $2}'"
    os_version = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()

    print('running df')
    cmd_df = "df --output=avail -BG /var/lib/docker | tail -n1 | awk '{print $1}'"
    free_space = subprocess.check_output(cmd_df, shell=True).decode('utf-8').strip()[:-1]


    print("checking errors")
    cmd_df = "grep -e 'device error' -e 'nvml error' kaalia.log | tail -n 1"
    device_error = subprocess.check_output(cmd_df, shell=True).decode('utf-8')

    cmd_df = "sudo timeout --foreground 3s journalctl -o short-precise -r -k --since '24 hours ago' -g 'AER' -n 1"
    cmd_df = "sudo timeout --foreground 3s journalctl -o short-precise -r -k --since '24 hours ago' | grep 'AER' | tail -n 1"
    aer_error = subprocess.check_output(cmd_df, shell=True).decode('utf-8')
    if len(aer_error) < 4:
        aer_error = None

    cmd_df = "sudo timeout --foreground 3s journalctl -o short-precise -r -k --since '24 hours ago' -g 'Uncorrected' -n 1"
    cmd_df = "sudo timeout --foreground 3s journalctl -o short-precise -r -k --since '24 hours ago' | grep 'Uncorrected' | tail -n 1"
    uncorr_error = subprocess.check_output(cmd_df, shell=True).decode('utf-8')
    if len(uncorr_error) < 4:
        uncorr_error = None

    aer_error = uncorr_error or aer_error


    try:
        disable_unattended_upgrades()
    except:
        pass

    print("nvidia-smi")
    nv_driver_version = get_nvidia_driver_version()
    print(nv_driver_version)

    cond_install("fio")

    bwu_cur = bwd_cur = None
    speedtest_found = False

    print("checking speedtest")
    try:
        r = random.randint(0, 8) 
        if r == 3 or args.speedtest:
            print("speedtest")
            try:
                # 根据参数选择测速方式
                if args.local_speedtest:
                    print("Using local speedtest (forced by --local-speedtest)")
                    output = epsilon_greedyish_speedtest()
                else:
                    # 优先使用远程 VPS 测速
                    output = remote_speedtest_via_vps(vps_host=args.vps_host, vps_user=args.vps_user)
                    
                    # 如果远程测速失败，回退到本地测速
                    if output is None:
                        print("Remote speedtest failed, falling back to local speedtest")
                        output = epsilon_greedyish_speedtest()
            except subprocess.CalledProcessError as e:
                output = e.output.decode('utf-8')
                print(output)
                output = None


            print(output)
            jomsg = json.loads(output)
            _MiB = 2 ** 20
            try:
                bwu_cur = 8*jomsg["upload"]["bandwidth"] / _MiB
                bwd_cur = 8*jomsg["download"]["bandwidth"] / _MiB
            except Exception as e:
                bwu_cur = 8*jomsg["upload"] / _MiB
                bwd_cur = 8*jomsg["download"] / _MiB

            #return json.dumps({"bwu_cur": bwu_cur, "bwd_cur": bwd_cur})

    except Exception as e:
        print("Exception:")
        print(e)
        print(output)

    disk_prodname = None

    try:
        docker_drive  = find_drive_of_mountpoint("/var/lib/docker")
        disk_prodname = subprocess.check_output(f"cat /sys/block/{docker_drive[5:]}/device/model",  shell=True).decode('utf-8')
        disk_prodname = disk_prodname.strip()
        print(f'found disk_name:{disk_prodname} from {docker_drive}')
    except:
        pass


    try:
        r = random.randint(0, 48)
        if r == 31:    
            print('cleaning build cache')
            output  = subprocess.check_output("docker builder prune --force",  shell=True).decode('utf-8')
            print(output)
    except:
        pass
    

    fio_command_read  = "sudo fio --numjobs=16 --ioengine=libaio --direct=1 --verify=0 --name=read_test  --directory=/var/lib/docker --bs=32k --iodepth=64 --size=128MB --readwrite=randread  --time_based --runtime=1.0s --group_reporting=1 --iodepth_batch_submit=64 --iodepth_batch_complete_max=64"
    fio_command_write = "sudo fio --numjobs=16 --ioengine=libaio --direct=1 --verify=0 --name=write_test --directory=/var/lib/docker --bs=32k --iodepth=64 --size=128MB --readwrite=randwrite --time_based --runtime=0.5s --group_reporting=1 --iodepth_batch_submit=64 --iodepth_batch_complete_max=64"

    print('running fio')
    # Parse the output to get the bandwidth (in MB/s)
    disk_read_bw  = None
    disk_write_bw = None


    try:
        output_read   = subprocess.check_output(fio_command_read,  shell=True).decode('utf-8')
        disk_read_bw  = float(output_read.split('bw=')[1].split('MiB/s')[0].strip())
    except:
        pass

    try:
        disk_read_bw  = float(output_read.split('bw=')[1].split('GiB/s')[0].strip()) * 1024.0
    except:
        pass


    try:
        output_write  = subprocess.check_output(fio_command_write, shell=True).decode('utf-8')
        disk_write_bw = float(output_write.split('bw=')[1].split('MiB/s')[0].strip())
    except:
        pass

    try:
        disk_write_bw  = float(output_write.split('bw=')[1].split('GiB/s')[0].strip()) * 1024.0
    except:
        pass

    total_pct, docker_pct, outside_pct = None, None, None
    try:
        total_pct, docker_pct, outside_pct = parse_cpu_stats()
    except:
        pass
    # Prepare the data for the POST request
    machine_update_data = {
        "mach_api_key": mach_api_key,
        "availram": int(free_space),
        "totalram": int(free_space) + get_used_disk_space_gb(path="/var/lib/docker"),
        "release_channel": get_channel(),
    }

    if os_version:
        machine_update_data["ubuntu_version"] = os_version

    if disk_read_bw:
        machine_update_data["bw_dev_cpu"] = disk_read_bw

    if disk_write_bw:
        machine_update_data["bw_cpu_dev"] = disk_write_bw

    if bwu_cur and bwu_cur > 0:
        machine_update_data["bwu_cur"] = bwu_cur

    if bwd_cur and bwd_cur > 0:
        machine_update_data["bwd_cur"] = bwd_cur

    if nv_driver_version:
        machine_update_data["driver_vers"] = nv_driver_version

    if disk_prodname:
        machine_update_data["product_name"] = disk_prodname

    if device_error and len(device_error) > 8:
        machine_update_data["error_msg"] = device_error

    if aer_error and len(aer_error) > 8:
        machine_update_data["aer_error"] = aer_error

    if total_pct:
        machine_update_data["cpu_total_pct"] = total_pct
    if docker_pct:
        machine_update_data["cpu_docker_pct"] = docker_pct
    if outside_pct:
        machine_update_data["cpu_outside_pct"] = outside_pct

    architecture = platform.machine()
    if architecture in ["AMD64", "amd64", "x86_64", "x86-64", "x64"]:
        machine_update_data["cpu_arch"] = "amd64"
    elif architecture in ["aarch64", "ARM64", "arm64"]:
        machine_update_data["cpu_arch"] = "arm64"
    else:
        machine_update_data["cpu_arch"] = "amd64"

    try:
        with open("/var/lib/vastai_kaalia/data/nvidia_smi.json", mode='r') as f:
            try:
                machine_update_data["gpu_arch"] = json.loads(f.read())["gpu_arch"]
            except:
                machine_update_data["gpu_arch"] = "nvidia"
            print(f"got gpu_arch: {machine_update_data['gpu_arch']}")
    except:
        pass

    try:
        machine_update_data["iommu_virtualizable"] = check_if_iommu_ok(gpus_by_iommu_by_index(), devices_by_iommu_by_index())
        print(f"got iommu virtualization capability: {machine_update_data['iommu_virtualizable']}")
    except:
        pass
    try:
        vm_status = is_vms_enabled()
        machine_update_data["vms_enabled"] = vm_status and machine_update_data["iommu_virtualizable"]
        if vm_status:
            if not machine_update_data["iommu_virtualizable"]:
                machine_update_data["vm_error_msg"] = "IOMMU config or Nvidia DRM Modeset has changed to no longer support VMs"
            if not subprocess.run(
                    ["systemctl", "is-active", "gdm"],
                ).returncode:
                machine_update_data["vm_error_msg"] = "GDM is on; VMs will no longer work."
        print(f"Got VM feature enablement status: {vm_status}")
    except:
        pass

    try:
        containerNames_to_startTimes = get_container_start_times()
        machine_update_data["container_startTimes"] = containerNames_to_startTimes
        print(f"Got container start times: {containerNames_to_startTimes}")
    except Exception as e:
        print(f"Exception Occured: {e}")

    # Perform the POST request
    response = requests.put(args.server+'/api/v0/disks/update/', json=machine_update_data)

    if response.status_code == 404 and mach_api_key.strip() != mach_api_key:
        print("Machine not found, retrying with stripped api key...")
        machine_update_data["mach_api_key"] = mach_api_key.strip()
        print(machine_update_data)
        response = requests.put(args.server+'/api/v0/disks/update/', json=machine_update_data)
    # Check the response
    if response.status_code == 200:
        print("Data sent successfully.")
    else:
        print(response)
        print(f"Failed to send Data, status code: {response.status_code}.")

PYTHON_FILE_START
    
    # 替换占位符为实际的服务器地址
    sed -i "s/SPEEDTEST_SERVER_PLACEHOLDER/$SPEEDTEST_SERVER/g" "$temp_file"
    
    echo "$temp_file"
}

# 写入文件
write_modified_file() {
    print_info "写入修改后的文件..."
    
    local temp_file="$1"
    
    # 解锁文件
    print_info "解锁目标文件..."
    chattr -i "$TARGET_FILE" 2>/dev/null || true
    
    # 写入新内容
    cat "$temp_file" > "$TARGET_FILE"
    
    # 设置权限
    chmod 755 "$TARGET_FILE"
    
    # 锁定文件
    print_info "锁定目标文件..."
    chattr +i "$TARGET_FILE"
    
    # 清理临时文件
    rm -f "$temp_file"
    
    print_success "文件写入完成并已锁定"
}

# 验证修改
verify_modification() {
    print_info "验证修改..."
    
    # 检查远程测速函数是否存在
    if grep -q "def remote_speedtest_via_vps" "$TARGET_FILE"; then
        print_success "远程测速函数已添加"
    else
        print_error "远程测速函数未找到"
        return 1
    fi
    
    # 检查服务器地址是否正确
    if grep -q "vps_host=\"$SPEEDTEST_SERVER\"" "$TARGET_FILE"; then
        print_success "测速服务器地址已配置: $SPEEDTEST_SERVER"
    else
        print_error "测速服务器地址配置失败"
        return 1
    fi
    
    # 检查默认参数是否正确
    if grep -q "default=\"$SPEEDTEST_SERVER\"" "$TARGET_FILE"; then
        print_success "默认参数已配置"
    else
        print_error "默认参数配置失败"
        return 1
    fi
    
    return 0
}

# 显示使用说明
show_usage_info() {
    echo ""
    print_success "安装完成！"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}配置信息${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "测速服务器: $SPEEDTEST_SERVER"
    echo "目标文件:   $TARGET_FILE"
    echo "配置文件:   $CONFIG_FILE"
    echo "备份目录:   $BACKUP_DIR"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}使用方法${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "1. 强制执行远程测速:"
    echo "   python3 $TARGET_FILE --speedtest"
    echo ""
    echo "2. 使用本地测速:"
    echo "   python3 $TARGET_FILE --speedtest --local-speedtest"
    echo ""
    echo "3. 更改测速服务器:"
    echo "   sudo bash $0"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}VPS 配置${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "在 VPS ($SPEEDTEST_SERVER) 上执行:"
    echo "  docker pull vastai/test:speedtest"
    echo ""
    echo "配置 SSH 密钥（推荐）:"
    echo "  ssh-copy-id root@$SPEEDTEST_SERVER"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# 主函数
main() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${BLUE}远程测速自动安装脚本${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # 检查权限
    check_root
    
    # 检查目标文件
    check_target_file
    
    # 获取测速服务器地址
    get_speedtest_server
    
    # 测试 SSH 连接（可选）
    test_ssh_connection || true
    
    # 检查是否已修改
    if check_if_already_modified; then
        print_info "文件已包含远程测速功能，将更新服务器地址"
    fi
    
    # 创建备份
    create_backup
    
    # 生成修改后的文件
    temp_file=$(generate_modified_file)
    
    # 写入文件
    write_modified_file "$temp_file"
    
    # 验证修改
    if verify_modification; then
        show_usage_info
        exit 0
    else
        print_error "验证失败，请检查文件"
        exit 1
    fi
}

# 运行主函数
main
