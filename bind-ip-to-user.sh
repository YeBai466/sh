#!/usr/bin/env bash
# =========================================================
# bind-ip-manager-v2.sh  —  多IP绑定管理器 (Debian 12 + Vultr)
# 作者：ChatGPT 2025-10
# =========================================================
set -euo pipefail

# ----------- 工具函数 -----------
echoinfo(){ echo -e "\e[34m[INFO]\e[0m $*"; }
echowarn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
echoerr(){ echo -e "\e[31m[ERROR]\e[0m $*" >&2; }
require_root(){ [ "$(id -u)" -eq 0 ] || { echoerr "请用 root 运行"; exit 1; }; }
main_iface(){ ip route | awk '/default/ {print $5; exit}'; }
get_gw(){ ip route show default 0.0.0.0/0 | awk '/default/ {print $3; exit}'; }

# ----------- 查看当前绑定 -----------
show_bindings(){
  echo
  echoinfo "当前绑定列表："
  found=0
  for svc in /etc/systemd/system/bind-u*-ip.service; do
    [ -f "$svc" ] || continue
    uid=$(grep -oP 'UID=\K[0-9]+' "$svc" || true)
    ip=$(grep -oP 'src\s+\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$svc" || true)
    user=$(getent passwd "$uid" | cut -d: -f1 || echo "未知")
    echo "  - 用户: $user (UID=$uid)  IP=$ip"
    found=1
  done
  [ $found -eq 0 ] && echowarn "暂无绑定记录。"
}

# ----------- 删除绑定 -----------
delete_binding(){
  show_bindings
  echo
  read -rp "输入要删除的用户名: " deluser
  [ -z "$deluser" ] && echowarn "取消删除。" && return
  if ! id "$deluser" &>/dev/null; then echowarn "用户不存在"; return; fi
  uid=$(id -u "$deluser")
  echoinfo "清理 $deluser ..."
  systemctl stop "bind-u${uid}-ip.service" 2>/dev/null || true
  systemctl disable "bind-u${uid}-ip.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/bind-u${uid}-ip.service"
  iptables -t mangle -S OUTPUT | grep -- "--uid-owner $uid" | while read -r r; do iptables -t mangle ${r/-A/-D} || true; done
  iptables -t nat -S POSTROUTING | grep -- "--mark $((uid+1000))" | while read -r r; do iptables -t nat ${r/-A/-D} || true; done
  ip rule show | grep "u${uid}_tbl" | awk '{print $1}' | while read -r p; do ip rule del pref "$p" || true; done
  sed -i "/u${uid}_tbl/d" /etc/iproute2/rt_tables || true
  ip route flush table "u${uid}_tbl" 2>/dev/null || true
  echoinfo "✅ 已删除 $deluser 的绑定。"
}

# ----------- 添加绑定 -----------
add_binding(){
  IFACE=$(main_iface)
  GW=$(get_gw)
  echoinfo "检测到主接口：$IFACE"
  echoinfo "检测到默认网关：$GW"

  mapfile -t IPS < <(ip -4 addr show dev "$IFACE" | awk '/inet /{print $2}')
  echo; echoinfo "可选 IP："
  i=1; for ip in "${IPS[@]}"; do echo " [$i] $ip"; ((i++)); done
  read -rp "选择编号: " c
  SEL_IP="${IPS[$((c-1))]%%/*}"
  echo; read -rp "输入用户名: " U
  id "$U" &>/dev/null || { useradd -m -s /bin/bash "$U"; echoinfo "已创建用户 $U"; }
  UIDNUM=$(id -u "$U")
  TABLE_NAME="u${UIDNUM}_tbl"; TABLE_ID=$((100+UIDNUM%900)); MARK=$((UIDNUM+1000))

  grep -q "$TABLE_NAME" /etc/iproute2/rt_tables || echo "$TABLE_ID $TABLE_NAME" >> /etc/iproute2/rt_tables
  ip route flush table "$TABLE_NAME" || true
  ip route add default via "$GW" dev "$IFACE" src "$SEL_IP" table "$TABLE_NAME"
  ip rule del fwmark "$MARK" table "$TABLE_NAME" 2>/dev/null || true
  ip rule add fwmark "$MARK" table "$TABLE_NAME" pref 500

  iptables -t mangle -A OUTPUT -m owner --uid-owner "$UIDNUM" -j MARK --set-xmark "$MARK"/0xffffffff

  echoinfo "检测出口..."
  out=$(sudo -u "$U" curl -4 -s --max-time 4 ifconfig.me || echo "N/A")
  if [[ "$out" != "$SEL_IP" ]]; then
    echowarn "检测到未生效，添加 SNAT 规则。"
    iptables -t nat -A POSTROUTING -m mark --mark "$MARK" -j SNAT --to-source "$SEL_IP"
  fi

  echoinfo "验证..."
  out=$(sudo -u "$U" curl -4 -s --max-time 4 ifconfig.me || echo "N/A")
  [[ "$out" == "$SEL_IP" ]] && echoinfo "✅ 成功绑定 $U 到 $SEL_IP" || echowarn "❌ 仍未生效：$out"

  SRV="/etc/systemd/system/bind-u${UIDNUM}-ip.service"
  cat >"$SRV"<<EOF
[Unit]
Description=Bind IP $SEL_IP to user $U
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
Environment="UID=$UIDNUM"
ExecStart=/bin/bash -c '
ip route flush table $TABLE_NAME 2>/dev/null || true
ip route add default via $GW dev $IFACE src $SEL_IP table $TABLE_NAME
ip rule add fwmark $MARK table $TABLE_NAME pref 500 2>/dev/null || true
iptables -t mangle -A OUTPUT -m owner --uid-owner $UID -j MARK --set-xmark $MARK/0xffffffff
iptables -t nat -A POSTROUTING -m mark --mark $MARK -j SNAT --to-source $SEL_IP || true
'
ExecStop=/bin/bash -c '
iptables -t mangle -D OUTPUT -m owner --uid-owner $UID -j MARK --set-xmark $MARK/0xffffffff 2>/dev/null || true
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

# ----------- 菜单 -----------
menu(){
  clear
  echo "==============================="
  echo "  多IP绑定管理工具 (Debian12)"
  echo "==============================="
  echo "  [1] 查看当前绑定"
  echo "  [2] 删除绑定"
  echo "  [3] 添加新绑定"
  echo "  [4] 退出"
  echo "-------------------------------"
  read -rp "请选择操作: " opt
  case "$opt" in
    1) show_bindings ;;
    2) delete_binding ;;
    3) add_binding ;;
    4) echoinfo "已退出"; exit 0 ;;
    *) echowarn "无效输入" ;;
  esac
  echo; read -rp "按回车返回菜单..." dummy
  menu
}

# ----------- 主流程 -----------
require_root
menu
