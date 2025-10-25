#!/usr/bin/env bash
set -euo pipefail

echoinfo(){ echo -e "\e[34m[INFO]\e[0m $*"; }
echowarn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
echoerr(){ echo -e "\e[31m[ERROR]\e[0m $*" >&2; }

require_root(){ [ "$(id -u)" -eq 0 ] || { echoerr "请以 root 运行"; exit 1; }; }
main_iface(){ ip route | awk '/default/ {print $5; exit}'; }
get_gw(){ ip route show default 0.0.0.0/0 | awk '/default/ {print $3; exit}'; }

fix_old_units(){
  for f in /etc/systemd/system/bind-u*-ip.service; do
    [ -f "$f" ] || continue
    sed -i '/Environment=/d' "$f" 2>/dev/null || true
  done
  systemctl daemon-reload
}

show_bindings(){
  echo; echoinfo "当前绑定："
  found=0
  for s in /etc/systemd/system/bind-u*-ip.service; do
    [ -f "$s" ] || continue
    ip=$(grep -oP 'SNAT --to-source \K[0-9.]+|src \K[0-9.]+' "$s" | head -n1)
    uid=$(grep -oP 'uid-owner \K[0-9]+' "$s" | head -n1)
    user=$(getent passwd "$uid" | cut -d: -f1 2>/dev/null || echo "未知")
    echo "  - 用户: $user (UID=$uid) → $ip"
    found=1
  done
  [ $found -eq 0 ] && echowarn "暂无绑定。"
}

delete_binding(){
  show_bindings
  echo; read -rp "输入要删除的用户名: " U
  [ -z "$U" ] && return
  if ! id "$U" &>/dev/null; then echowarn "用户不存在"; return; fi
  uid=$(id -u "$U")
  echoinfo "清理 $U..."
  systemctl stop "bind-u${uid}-ip.service" 2>/dev/null || true
  systemctl disable "bind-u${uid}-ip.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/bind-u${uid}-ip.service"
  iptables -t mangle -S OUTPUT | grep -- "--uid-owner $uid" | while read -r r; do iptables -t mangle ${r/-A/-D} || true; done
  iptables -t nat -S POSTROUTING | grep -- "--mark $((uid+1000))" | while read -r r; do iptables -t nat ${r/-A/-D} || true; done
  ip rule show | grep "u${uid}_tbl" | awk '{print $1}' | while read -r p; do ip rule del pref "$p" || true; done
  sed -i "/u${uid}_tbl/d" /etc/iproute2/rt_tables || true
  ip route flush table "u${uid}_tbl" 2>/dev/null || true
  echoinfo "✅ 已删除 $U 的绑定。"
}

add_binding(){
  IFACE=$(main_iface)
  GW=$(get_gw)
  echoinfo "接口：$IFACE 网关：$GW"
  mapfile -t IPS < <(ip -4 addr show dev "$IFACE" | awk '/inet /{print $2}')
  echo; i=1; for ip in "${IPS[@]}"; do echo " [$i] $ip"; ((i++)); done
  read -rp "选择编号: " c
  SEL_IP="${IPS[$((c-1))]%%/*}"
  read -rp "用户名: " U
  id "$U" &>/dev/null || { useradd -m -s /bin/bash "$U"; echoinfo "创建用户 $U"; }
  UIDNUM=$(id -u "$U"); TABLE="u${UIDNUM}_tbl"; MARK=$((UIDNUM+1000))
  grep -q "$TABLE" /etc/iproute2/rt_tables || echo "$((100+UIDNUM%900)) $TABLE" >> /etc/iproute2/rt_tables
  ip route flush table "$TABLE" 2>/dev/null || true
  ip route add default via "$GW" dev "$IFACE" src "$SEL_IP" table "$TABLE"
  ip rule del fwmark "$MARK" table "$TABLE" 2>/dev/null || true
  ip rule add fwmark "$MARK" table "$TABLE" pref 500
  iptables -t mangle -A OUTPUT -m owner --uid-owner "$UIDNUM" -j MARK --set-xmark "$MARK"/0xffffffff

  out=$(sudo -u "$U" curl -4 -s --max-time 4 ifconfig.me || echo "")
  if [[ "$out" != "$SEL_IP" ]]; then
    echowarn "SNAT 启用..."
    iptables -t nat -A POSTROUTING -m mark --mark "$MARK" -j SNAT --to-source "$SEL_IP"
  fi
  out=$(sudo -u "$U" curl -4 -s --max-time 4 ifconfig.me || echo "")
  [[ "$out" == "$SEL_IP" ]] && echoinfo "✅ 成功绑定 $U 到 $SEL_IP" || echowarn "❌ 出口仍是 $out"

  SRV="/etc/systemd/system/bind-u${UIDNUM}-ip.service"
  cat >"$SRV"<<EOF
[Unit]
Description=Bind IP $SEL_IP to user $U
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '
ip route flush table $TABLE 2>/dev/null || true
ip route add default via $GW dev $IFACE src $SEL_IP table $TABLE
ip rule add fwmark $MARK table $TABLE pref 500 2>/dev/null || true
iptables -t mangle -A OUTPUT -m owner --uid-owner $UIDNUM -j MARK --set-xmark $MARK/0xffffffff
iptables -t nat -A POSTROUTING -m mark --mark $MARK -j SNAT --to-source $SEL_IP || true
'
ExecStop=/bin/bash -c '
iptables -t mangle -D OUTPUT -m owner --uid-owner $UIDNUM -j MARK --set-xmark $MARK/0xffffffff 2>/dev/null || true
iptables -t nat -D POSTROUTING -m mark --mark $MARK -j SNAT --to-source $SEL_IP 2>/dev/null || true
ip rule del fwmark $MARK table $TABLE 2>/dev/null || true
ip route flush table $TABLE 2>/dev/null || true
'

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "bind-u${UIDNUM}-ip.service"
}

menu(){
  clear
  echo "==============================="
  echo "  多IP绑定管理工具 (Debian12)"
  echo "==============================="
  echo "  [1] 查看绑定"
  echo "  [2] 删除绑定"
  echo "  [3] 添加绑定"
  echo "  [4] 退出"
  echo "-------------------------------"
  read -rp "选择: " opt
  case "$opt" in
    1) show_bindings ;;
    2) delete_binding ;;
    3) add_binding ;;
    4) echoinfo "退出"; exit 0 ;;
    *) echowarn "无效" ;;
  esac
  echo; read -rp "按回车返回..." _; menu
}

require_root
fix_old_units
menu
