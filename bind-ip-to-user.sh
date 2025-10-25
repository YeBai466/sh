#!/usr/bin/env bash
# =========================================================
# bind-ip-manager.sh — Debian 12 / Vultr 优化版
# 自动为指定用户绑定附加 IP（并管理之前的绑定）
# 作者: ChatGPT (2025-10)
# =========================================================

set -euo pipefail

# ------------------ Helper ------------------
echoinfo(){ echo -e "\e[34m[INFO]\e[0m $*"; }
echowarn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
echoerr(){ echo -e "\e[31m[ERROR]\e[0m $*" >&2; }

require_root(){
  if [ "$(id -u)" -ne 0 ]; then
    echoerr "请以 root 身份运行此脚本。"
    exit 1
  fi
}

main_iface() {
  ip route | awk '/default/ {print $5; exit}'
}

get_default_gateway(){
  ip route show default 0.0.0.0/0 | awk '/default/ {print $3; exit}'
}

pause_enter(){ read -rp "按 Enter 继续..." ; }

# ------------------ Step 1: 显示当前绑定 ------------------
list_existing_bindings(){
  echo
  echoinfo "当前绑定的用户与 IP（从 systemd service 推断）:"
  systemctl list-unit-files | grep bind-u | awk '{print $1}' | while read -r svc; do
    [[ -z "$svc" ]] && continue
    file="/etc/systemd/system/$svc"
    if [ -f "$file" ]; then
      uid=$(grep -oP 'user\s+\K[0-9]+' "$file" | head -n1 || true)
      ip=$(grep -oP 'src\s+\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$file" | head -n1 || true)
      echo "  - $svc   (UID=$uid, IP=$ip)"
    fi
  done || true
}

remove_binding(){
  echo
  echoinfo "输入要删除的用户名（或留空跳过）："
  read -rp "User: " del_user
  [[ -z "$del_user" ]] && return

  uid=$(id -u "$del_user" 2>/dev/null || true)
  [[ -z "$uid" ]] && echowarn "用户不存在，跳过清理。" && return

  echoinfo "正在清理用户 $del_user 的规则..."

  # 停止并禁用 systemd
  systemctl stop "bind-u${uid}-ip.service" 2>/dev/null || true
  systemctl disable "bind-u${uid}-ip.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/bind-u${uid}-ip.service" 2>/dev/null || true

  # 删除 iptables 规则
  while iptables -t mangle -S OUTPUT | grep -q -- "--uid-owner $uid"; do
    rule=$(iptables -t mangle -S OUTPUT | grep -- "--uid-owner $uid" | head -n1)
    del=${rule/-A/-D}
    iptables -t mangle $del || true
  done

  # 删除 NAT
  while iptables -t nat -S POSTROUTING | grep -q -- "--mark $((uid+1000))"; do
    rule=$(iptables -t nat -S POSTROUTING | grep -- "--mark $((uid+1000))" | head -n1)
    del=${rule/-A/-D}
    iptables -t nat $del || true
  done

  # 删除 ip rule 和表
  ip rule show | grep "u${uid}_tbl" | awk '{print $1}' | while read -r pr; do
    ip rule del pref "$pr" 2>/dev/null || true
  done
  sed -i "/u${uid}_tbl/d" /etc/iproute2/rt_tables 2>/dev/null || true
  ip route flush table "u${uid}_tbl" 2>/dev/null || true

  echoinfo "已清理完成用户 $del_user 的绑定。"
}

# ------------------ Step 2: 扫描 IP ------------------
scan_ips(){
  IFACE=$(main_iface)
  echoinfo "主接口为：$IFACE"
  mapfile -t IPS < <(ip -4 addr show dev "$IFACE" | awk '/inet /{print $2}')
  if [ "${#IPS[@]}" -eq 0 ]; then
    echoerr "未找到 IP 地址，请检查网络配置。"
    exit 1
  fi
  echo
  echoinfo "检测到以下 IPv4 地址："
  i=1
  for ip in "${IPS[@]}"; do
    echo "  [$i] $ip"
    ((i++))
  done
  echo "  [0] 退出"
  echo
  read -rp "请选择要绑定的 IP 编号: " choice
  [[ "$choice" == "0" ]] && exit 0
  SEL_IP="${IPS[$((choice-1))]%%/*}"
  echoinfo "选择 IP: $SEL_IP"
}

# ------------------ Step 3: 创建或选择用户 ------------------
select_user(){
  read -rp "输入要绑定的用户名: " USERNAME
  if id "$USERNAME" &>/dev/null; then
    echowarn "用户已存在，将覆盖绑定。"
  else
    echoinfo "创建新用户 $USERNAME"
    useradd -m -s /bin/bash "$USERNAME"
  fi
  USER_UID=$(id -u "$USERNAME")
}

# ------------------ Step 4: 应用绑定 ------------------
apply_binding(){
  TABLE_ID=$((100 + (USER_UID % 900)))
  TABLE_NAME="u${USER_UID}_tbl"
  MARK=$((USER_UID + 1000))
  GW=$(get_default_gateway)
  IFACE=$(main_iface)

  echoinfo "配置路由表 $TABLE_NAME (ID=$TABLE_ID), via $GW dev $IFACE src $SEL_IP"

  grep -q "$TABLE_NAME" /etc/iproute2/rt_tables 2>/dev/null || \
    echo "$TABLE_ID  $TABLE_NAME" >> /etc/iproute2/rt_tables

  ip route flush table "$TABLE_NAME" 2>/dev/null || true
  ip route add default via "$GW" dev "$IFACE" src "$SEL_IP" table "$TABLE_NAME"
  ip route add "$SEL_IP/32" dev "$IFACE" table "$TABLE_NAME" || true

  ip rule del fwmark "$MARK" table "$TABLE_NAME" 2>/dev/null || true
  ip rule add fwmark "$MARK" table "$TABLE_NAME" pref 500

  # 清理旧 mangle
  while iptables -t mangle -S OUTPUT | grep -q -- "--uid-owner $USER_UID"; do
    rule=$(iptables -t mangle -S OUTPUT | grep -- "--uid-owner $USER_UID" | head -n1)
    del=${rule/-A/-D}
    iptables -t mangle $del || true
  done

  iptables -t mangle -A OUTPUT -m owner --uid-owner "$USER_UID" -j MARK --set-xmark "$MARK"/0xffffffff

  # 检测是否需要 SNAT
  echoinfo "检测 SNAT 需求..."
  if ! sudo -u "$USERNAME" curl -s --max-time 3 ifconfig.me | grep -q "$SEL_IP"; then
    echowarn "检测到未生效，将添加 SNAT 规则。"
    iptables -t nat -A POSTROUTING -m mark --mark "$MARK" -j SNAT --to-source "$SEL_IP"
  fi

  # 验证
  echoinfo "验证出口 IP..."
  test_ip=$(sudo -u "$USERNAME" curl -s --max-time 5 ifconfig.me || echo "N/A")
  echoinfo "结果：$test_ip"
  if [[ "$test_ip" == "$SEL_IP" ]]; then
    echoinfo "✅ 成功：用户 $USERNAME 的出口 IP 为 $SEL_IP"
  else
    echowarn "❌ 未成功：出口 IP 仍为 $test_ip，请检查网络或 SNAT。"
  fi

  # systemd 持久化
  SRV="/etc/systemd/system/bind-u${USER_UID}-ip.service"
  echoinfo "写入 systemd 单元：$SRV"
  cat > "$SRV" <<EOF
[Unit]
Description=Bind IP $SEL_IP to user $USERNAME
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '
ip route flush table $TABLE_NAME 2>/dev/null || true
ip route add default via $GW dev $IFACE src $SEL_IP table $TABLE_NAME
ip route add $SEL_IP/32 dev $IFACE table $TABLE_NAME
ip rule add fwmark $MARK table $TABLE_NAME pref 500 2>/dev/null || true
iptables -t mangle -A OUTPUT -m owner --uid-owner $USER_UID -j MARK --set-xmark $MARK/0xffffffff
iptables -t nat -A POSTROUTING -m mark --mark $MARK -j SNAT --to-source $SEL_IP || true
'
ExecStop=/bin/bash -c '
iptables -t mangle -D OUTPUT -m owner --uid-owner $USER_UID -j MARK --set-xmark $MARK/0xffffffff 2>/dev/null || true
iptables -t nat -D POSTROUTING -m mark --mark $MARK -j SNAT --to-source $SEL_IP 2>/dev/null || true
ip rule del fwmark $MARK table $TABLE_NAME 2>/dev/null || true
ip route flush table $TABLE_NAME 2>/dev/null || true
'
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "$(basename "$SRV")"
}

# ------------------ Main ------------------
require_root
list_existing_bindings
remove_binding
scan_ips
select_user
apply_binding

echoinfo "操作完成。重启后规则会自动生效。"
