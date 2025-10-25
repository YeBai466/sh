#!/usr/bin/env bash
set -euo pipefail

# bind-ip-to-user.sh
# Debian 12
# 用法：以 root 运行： ./bind-ip-to-user.sh

# ---------- helpers ----------
echoinfo(){ echo -e "\e[34m[INFO]\e[0m $*"; }
echoerr(){ echo -e "\e[31m[ERROR]\e[0m $*" >&2; }
echowarn(){ echo -e "\e[33m[WARN]\e[0m $*"; }

require_root(){
  if [ "$(id -u)" -ne 0 ]; then
    echoerr "请以 root 用户运行此脚本。"
    exit 1
  fi
}

pause_enter(){
  read -rp "按 Enter 继续..."
}

# ---------- scan IPs ----------
scan_ips(){
  # 输出格式: index|ifname|ip|prefix
  # 只列出 scope global 的 IPv4 地址（排除 loopback、link-local）
  mapfile -t ADDR_LINES < <(ip -4 addr show scope global | awk '/inet /{print $2 " " $NF}' )
  IPS=()
  IFS=$'\n'
  idx=1
  for line in "${ADDR_LINES[@]}"; do
    ipnet=$(echo "$line" | awk '{print $1}')
    ifname=$(echo "$line" | awk '{print $2}')
    ipaddr=${ipnet%%/*}
    prefix=${ipnet##*/}
    IPS+=("$ifname|$ipaddr|$prefix")
  done
  unset IFS
}

show_ip_menu(){
  echo
  echoinfo "检测到以下 IPv4 地址（scope global）："
  i=1
  for item in "${IPS[@]}"; do
    ifname=$(echo "$item" | cut -d'|' -f1)
    ipaddr=$(echo "$item" | cut -d'|' -f2)
    prefix=$(echo "$item" | cut -d'|' -f3)
    echo "  [$i] Interface: $ifname    IP: $ipaddr/$prefix"
    ((i++))
  done
  echo "  [0] 退出"
  echo
  echo "请按数字键选择你要绑定的 IP（单键，不需回车），例如按 1："
  # read -n1 读取单键（小键盘/数字键都可）
  while true; do
    read -n1 -s choice
    echo    # 换行以便显示
    if [[ "$choice" =~ ^[0-9]+$ ]]; then
      if [ "$choice" -eq 0 ]; then
        echoinfo "退出。"
        exit 0
      fi
      if [ "$choice" -ge 1 ] && [ "$choice" -le "${#IPS[@]}" ]; then
        SEL_INDEX=$((choice-1))
        SEL_ITEM=${IPS[$SEL_INDEX]}
        SEL_IF=$(echo "$SEL_ITEM" | cut -d'|' -f1)
        SEL_IP=$(echo "$SEL_ITEM" | cut -d'|' -f2)
        SEL_PREFIX=$(echo "$SEL_ITEM" | cut -d'|' -f3)
        echoinfo "选择： $SEL_IF  $SEL_IP/$SEL_PREFIX"
        break
      fi
    fi
    echowarn "无效选择，请按有效数字键（0-${#IPS[@]})。"
  done
}

# ---------- get default gateway (尝试) ----------
get_default_gateway(){
  # 试图找出默认网关（通常提供商会使用同一网关）
  DEFAULT_GW=$(ip route show default 0.0.0.0/0 | awk '/default/ {print $3; exit}')
  if [ -z "$DEFAULT_GW" ]; then
    echowarn "未检测到默认网关，请手动输入网关 IP（通常是提供商分配的网关）:"
    read -rp "Gateway: " DEFAULT_GW
  else
    echoinfo "检测到默认网关: $DEFAULT_GW"
  fi
}

# ---------- create or rewrite user ----------
create_or_rewrite_user(){
  echo
  read -rp "请输入要绑定的用户名 (例如 test1)： " TARGET_USER
  if id "$TARGET_USER" &>/dev/null; then
    echowarn "用户 $TARGET_USER 已存在。将覆盖/重新配置绑定（不会删除用户）。"
    read -rp "是否继续并覆盖绑定配置？(y/N): " yn
    if [[ ! "$yn" =~ ^[Yy]$ ]]; then
      echoinfo "取消。"
      exit 0
    fi
    USER_EXISTS=1
  else
    echoinfo "将创建用户 $TARGET_USER（家目录 /home/$TARGET_USER）"
    read -rp "是否设定密码？若留空则不会设置（可稍后手动设置）: " PW
    if [ -n "$PW" ]; then
      useradd -m -s /bin/bash "$TARGET_USER"
      echo "$TARGET_USER:$PW" | chpasswd
    else
      useradd -m -s /bin/bash "$TARGET_USER"
    fi
    USER_EXISTS=0
  fi
  TARGET_UID=$(id -u "$TARGET_USER")
  echoinfo "用户 $TARGET_USER 的 UID = $TARGET_UID"
}

# ---------- cleanup old rules for a given user (if exist) ----------
cleanup_user_rules(){
  # 清理之前可能存在的 iptables mangle 标记 & ip rule & custom routing table entries
  # 我们用保守方法：查找并删除所有基于 uid 的 mangle OUTPUT 规则（匹配该 UID）
  echoinfo "清理 $TARGET_USER 可能已有的旧规则..."
  # 删除 mangle 中以匹配 uid 的规则（注意：iptables 可能有多个）
  while iptables -t mangle -S OUTPUT 2>/dev/null | grep -q -- "--uid-owner $TARGET_UID"; do
    # 找第一条匹配的规则并删除（解析其序号）
    # 获取完整规则行
    RULE_LINE=$(iptables -t mangle -S OUTPUT | grep -- "--uid-owner $TARGET_UID" | head -n1)
    # transform -S output to -D form: replace -A OUTPUT with -D OUTPUT
    DEL_RULE=${RULE_LINE/-A/-D}
    iptables -t mangle $DEL_RULE || true
  done

  # 删除 ip rule 中基于 fwmark 的规则（我们使用 mark 值根据 uid，见下文）
  # We'll search for rules with "from all" or fwmark referencing our mark pattern; but easier: remove any rule with comment we add.
  # We add rules with "pref 100" maybe; but to be safe, remove rules that reference a table created for this user (table name contains uid).
  # We'll track created table name later. For now, also delete rules whose lookup table matches pattern "u<UID>_tbl"
  ip rule show | while read -r line; do
    if echo "$line" | grep -q "u${TARGET_UID}_tbl"; then
      # get priority number (first field)
      PRI=$(echo "$line" | awk '{print $1}')
      ip rule del pref "$PRI" || true
    fi
  done

  # Remove custom route tables we might have added to /etc/iproute2/rt_tables (best-effort)
  if grep -q "u${TARGET_UID}_tbl" /etc/iproute2/rt_tables 2>/dev/null; then
    echoinfo "从 /etc/iproute2/rt_tables 中移除旧表项 u${TARGET_UID}_tbl"
    sed -i.bak "/u${TARGET_UID}_tbl/d" /etc/iproute2/rt_tables || true
  fi
}

# ---------- configure routing + iptables rules ----------
configure_binding(){
  TABLE_ID=$((100 + (TARGET_UID % 1000)))   # table id 100..1099 之类（尽量避免与系统表冲突）
  TABLE_NAME="u${TARGET_UID}_tbl"
  MARK=$((TARGET_UID + 1000))               # fwmark 值（简易策略）
  echoinfo "将为用户 $TARGET_USER (UID=$TARGET_UID) 创建路由表 $TABLE_ID ($TABLE_NAME) 并使用 fwmark $MARK"

  # 在 /etc/iproute2/rt_tables 中注册表名（如果未存在）
  if ! grep -q "$TABLE_NAME" /etc/iproute2/rt_tables 2>/dev/null; then
    echo "$TABLE_ID    $TABLE_NAME" >> /etc/iproute2/rt_tables
    echoinfo "已在 /etc/iproute2/rt_tables 中添加: $TABLE_ID $TABLE_NAME"
  else
    echoinfo "路由表 $TABLE_NAME 已存在于 /etc/iproute2/rt_tables"
  fi

  # 添加路由表条目：默认路由走选择的网关，src 指定为 SEL_IP
  # 如果用户提供的网关不在同一网段，可能需要手动按提供商说明配置
  echoinfo "在路由表 $TABLE_NAME 中添加默认路由： via $DEFAULT_GW dev $SEL_IF src $SEL_IP"
  # 删除已存在同名规则以避免冲突
  ip route flush table "$TABLE_NAME" || true

  # 添加必要的路由（两个命令确保可达性）
  ip route add default via "$DEFAULT_GW" dev "$SEL_IF" src "$SEL_IP" table "$TABLE_NAME" || {
    echoerr "为路由表添加默认路由失败（尝试直接添加失败），请检查网卡/网关设置。"
  }

  # 为确保到本地 IP 的路由正确（有些环境要求）
  ip route add "$SEL_IP/32" dev "$SEL_IF" table "$TABLE_NAME" || true

  # 将标记包的规则与路由表关联：根据 fwmark 路由到表
  # 先删除可能已有同样的规则
  if ip rule show | grep -q "fwmark 0x$(printf '%x' "$MARK")"; then
    ip rule del fwmark "$MARK" table "$TABLE_NAME" || true
  fi
  ip rule add fwmark "$MARK" table "$TABLE_NAME" pref 500 || true

  # 在 mangle 表中：把该 UID 的所有 OUTPUT 打上 mark
  # 先删除旧规则（如果存在），简单方法是 remove any rule matching uid-owner and MARK; but we'll append rule with a comment and ensure no duplicates
  # Ensure iptables-save doesn't choke on comments in older versions; so we do matching deletion by uid
  # Remove any existing identical rule:
  while iptables -t mangle -S OUTPUT 2>/dev/null | grep -q -- "--uid-owner $TARGET_UID" ; do
    RULE_DEL=$(iptables -t mangle -S OUTPUT | grep -- "--uid-owner $TARGET_UID" | head -n1)
    # convert -A to -D
    RULE_DEL=${RULE_DEL/-A/-D}
    iptables -t mangle $RULE_DEL || true
  done

  # Add new rule
  iptables -t mangle -A OUTPUT -m owner --uid-owner "$TARGET_UID" -j MARK --set-xmark "$MARK"/0xffffffff

  echoinfo "已添加 iptables mangle 规则：所有 UID=$TARGET_UID 的输出将被标记 (mark=$MARK)"

  # 可选：如果你的环境要求做 SNAT（有些 VPS 提供商不需要），可以启用如下 nat 规则：
  # iptables -t nat -A POSTROUTING -m mark --mark $MARK -j SNAT --to-source $SEL_IP
  # 我默认不启用 nat SNAT，若你发现源 IP 不是期望的 SEL_IP，可取消注释上行。

  echoinfo "绑定配置已完成。请测试：以该用户身份发起连接并通过 'ip route get 1.1.1.1' 或 'curl ifconfig.me' 来验证出口IP。"

  # 打印快速检测命令提示
  echo
  echoinfo "快速检测命令示例（在主机上以 root 运行）："
  echo "  sudo -u $TARGET_USER ip -4 route get 1.1.1.1"
  echo "  sudo -u $TARGET_USER curl -s ifconfig.me || curl -s icanhazip.com"
}

# ---------- persistence: 可选生成 systemd unit ----------
offer_persistence(){
  echo
  echoinfo "是否要将这组规则写入 systemd unit，以便重启后自动恢复？(推荐) [y/N]"
  read -r resp
  if [[ "$resp" =~ ^[Yy]$ ]]; then
    SRV="/etc/systemd/system/bind-u${TARGET_UID}-ip.service"
    echoinfo "创建 systemd 单元 $SRV"
    cat > "$SRV" <<EOF
[Unit]
Description=Bind IP $SEL_IP to user $TARGET_USER (uid $TARGET_UID)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c ' \
/sbin/ip route flush table $TABLE_NAME 2>/dev/null || true; \
/sbin/ip route add default via $DEFAULT_GW dev $SEL_IF src $SEL_IP table $TABLE_NAME || true; \
/sbin/ip route add $SEL_IP/32 dev $SEL_IF table $TABLE_NAME || true; \
/sbin/ip rule add fwmark $MARK table $TABLE_NAME pref 500 2>/dev/null || true; \
/sbin/iptables -t mangle -D OUTPUT -m owner --uid-owner $TARGET_UID -j MARK --set-xmark $MARK/0xffffffff 2>/dev/null || true; \
/sbin/iptables -t mangle -A OUTPUT -m owner --uid-owner $TARGET_UID -j MARK --set-xmark $MARK/0xffffffff; \
'
ExecStop=/bin/bash -c ' \
/sbin/iptables -t mangle -D OUTPUT -m owner --uid-owner $TARGET_UID -j MARK --set-xmark $MARK/0xffffffff 2>/dev/null || true; \
/sbin/ip rule del fwmark $MARK table $TABLE_NAME 2>/dev/null || true; \
/sbin/ip route flush table $TABLE_NAME 2>/dev/null || true; \
'
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "bind-u${TARGET_UID}-ip.service"
    echoinfo "systemd 单元已启用并启动。你可以用 systemctl status bind-u${TARGET_UID}-ip.service 检查状态。"
  else
    echoinfo "未创建 systemd 单元。你可以手动保存上面配置的 ip/iptables 命令到启动脚本以实现持久化。"
  fi
}

# ---------- main ----------
require_root
scan_ips

if [ "${#IPS[@]}" -eq 0 ]; then
  echoerr "未检测到 scope global 的 IPv4 地址。请检查网络配置。"
  exit 1
fi

show_ip_menu
get_default_gateway
create_or_rewrite_user
cleanup_user_rules
configure_binding
offer_persistence

echoinfo "完成。"
exit 0
